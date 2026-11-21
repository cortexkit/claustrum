//! Signing-time match domains for the GitHub extractor. No HTTP is performed here.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Additional, Approval, Class, Constraints, GraphqlRequest, Identity, Kind, PolicyError,
    Predicate, Request, RuleSet,
};
use crate::gh_manifest::MAX_MANIFEST_JSON_INTEGER;

const MAX_OWNER_BASE_BYTES: usize = 39;
const MAX_OWNER_SUFFIX_BYTES: usize = 16;
const MAX_REPO_BYTES: usize = 100;
const MAX_ISSUE_NUMBER: u64 = 2_147_483_647;
const MAX_NAME_BYTES: usize = 255;
const MAX_TAIL_BYTES: usize = 1024;
const MAX_TAIL_PARAMETER_BYTES: usize = 32;
const GRAPHQL_HOST: &str = "api.github.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parameter {
    Owner,
    Repo,
    Number,
    Id,
    Sha,
    Name,
}

impl Parameter {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "owner" => Self::Owner,
            "repo" => Self::Repo,
            "number" => Self::Number,
            "id" => Self::Id,
            "sha" => Self::Sha,
            "name" => Self::Name,
            _ => return None,
        })
    }

    fn matches(self, s: &str) -> bool {
        match self {
            Self::Owner => {
                let (base, suffix) = s.split_once('_').map_or((s, None), |(a, b)| (a, Some(b)));
                let ascii_alnum = |b: u8| b.is_ascii_alphanumeric();
                (1..=MAX_OWNER_BASE_BYTES).contains(&base.len())
                    && base.as_bytes()[0].is_ascii_alphanumeric()
                    && base.as_bytes()[base.len() - 1].is_ascii_alphanumeric()
                    && base.bytes().all(|b| ascii_alnum(b) || b == b'-')
                    && suffix.is_none_or(|suffix| {
                        (1..=MAX_OWNER_SUFFIX_BYTES).contains(&suffix.len())
                            && suffix.bytes().all(ascii_alnum)
                    })
            }
            Self::Repo => {
                (1..=MAX_REPO_BYTES).contains(&s.len())
                    && !matches!(s, "." | "..")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            }
            Self::Number => decimal_within(s, MAX_ISSUE_NUMBER),
            Self::Id => decimal_within(s, MAX_MANIFEST_JSON_INTEGER as u64),
            Self::Sha => matches!(s.len(), 40 | 64) && super::lower_hex(s, s.len()),
            Self::Name => s.len() <= MAX_NAME_BYTES && normalized_segment(s),
        }
    }

    fn shortest(self) -> usize {
        if self == Self::Sha {
            40
        } else {
            1
        }
    }

    fn shortest_common(self, other: Self) -> Option<usize> {
        use Parameter::*;
        // All non-SHA types accept "1". A full SHA is too long to be an owner
        // without an enterprise suffix, or to be a decimal issue number or id.
        match (self, other) {
            (Sha, Owner | Number | Id) | (Owner | Number | Id, Sha) => None,
            (a, b) => Some(a.shortest().max(b.shortest())),
        }
    }
}

fn decimal_within(s: &str, max: u64) -> bool {
    s.as_bytes()
        .first()
        .is_some_and(|b| matches!(b, b'1'..=b'9'))
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u64>().is_ok_and(|n| n <= max)
}

fn normalized_segment(s: &str) -> bool {
    !matches!(s, "" | "." | "..")
        && !s
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b'/' | b'\\'))
}

pub(crate) fn valid_resource(resource: &str) -> bool {
    !resource.bytes().any(|b| b.is_ascii_uppercase())
        && resource.split_once('/').is_some_and(|(owner, repo)| {
            Parameter::Owner.matches(owner) && Parameter::Repo.matches(repo)
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Segment<'a> {
    Literal(&'a str),
    Typed(Parameter),
}

impl Segment<'_> {
    fn shortest_common(self, other: Self) -> Option<usize> {
        match (self, other) {
            (Self::Literal(a), Self::Literal(b)) => (a == b).then_some(a.len()),
            (Self::Literal(s), Self::Typed(t)) | (Self::Typed(t), Self::Literal(s)) => {
                t.matches(s).then_some(s.len())
            }
            (Self::Typed(a), Self::Typed(b)) => a.shortest_common(b),
        }
    }
}

#[derive(Debug)]
struct Path<'a> {
    prefix: Vec<Segment<'a>>,
    params: BTreeSet<&'a str>,
    tail: bool,
}

impl<'a> Path<'a> {
    fn parse(s: &'a str) -> Result<Self, PolicyError> {
        use PolicyError::*;
        let mut path = Self {
            prefix: Vec::new(),
            params: BTreeSet::new(),
            tail: false,
        };
        let segments = s.strip_prefix('/').ok_or(InvalidPath)?.split('/');
        let mut segments = segments.peekable();
        while let Some(segment) = segments.next() {
            if let Some(name) = segment.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
                if let Some(tail) = name.strip_suffix('*') {
                    if segments.peek().is_some() {
                        return Err(MisplacedTail);
                    }
                    if !(1..=MAX_TAIL_PARAMETER_BYTES).contains(&tail.len())
                        || !tail.as_bytes()[0].is_ascii_lowercase()
                        || !tail
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        return Err(UnknownPathParameter);
                    }
                    if !path.params.insert(tail) && matches!(tail, "owner" | "repo") {
                        return Err(RepeatedResourceParameter);
                    }
                    path.tail = true;
                } else {
                    let param = Parameter::parse(name).ok_or(UnknownPathParameter)?;
                    if !path.params.insert(name)
                        && matches!(param, Parameter::Owner | Parameter::Repo)
                    {
                        return Err(RepeatedResourceParameter);
                    }
                    path.prefix.push(Segment::Typed(param));
                }
            } else {
                if !normalized_segment(segment) || segment.contains(['{', '}']) {
                    return Err(InvalidPath);
                }
                path.prefix.push(Segment::Literal(segment));
            }
        }
        Ok(path)
    }

    fn has_param(&self, param: Parameter) -> bool {
        self.prefix.contains(&Segment::Typed(param))
    }

    fn overlaps(&self, other: &Self) -> bool {
        let min_self = self.prefix.len() + usize::from(self.tail);
        let min_other = other.prefix.len() + usize::from(other.tail);
        let count = min_self.max(min_other);
        if (!self.tail && count != min_self) || (!other.tail && count != min_other) {
            return false;
        }

        // A common path exists iff the shortest common segment at each position
        // fits the tail's total byte limit, counting the separators it consumes.
        let tail_segment = Segment::Typed(Parameter::Name);
        let (mut self_bytes, mut other_bytes) = (0, 0);
        for index in 0..count {
            let a = self.prefix.get(index).copied().unwrap_or(tail_segment);
            let b = other.prefix.get(index).copied().unwrap_or(tail_segment);
            let Some(bytes) = a.shortest_common(b) else {
                return false;
            };
            if index >= self.prefix.len() {
                self_bytes += bytes + usize::from(index != self.prefix.len());
            }
            if index >= other.prefix.len() {
                other_bytes += bytes + usize::from(index != other.prefix.len());
            }
        }
        self_bytes <= MAX_TAIL_BYTES && other_bytes <= MAX_TAIL_BYTES
    }
}

struct Domain<'a> {
    required: BTreeSet<&'a str>,
    optional: BTreeSet<&'a str>,
    fixed: BTreeMap<&'a str, &'a serde_json::Value>,
    forbidden: BTreeSet<&'a str>,
    allow_more: bool,
}

impl<'a> Domain<'a> {
    fn new(
        rules: Option<&'a Constraints>,
        allow_more_when_absent: bool,
    ) -> Result<Self, PolicyError> {
        let names = |list: Option<&'a Vec<String>>| {
            list.into_iter()
                .flatten()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        };
        let domain = Self {
            required: names(rules.and_then(|r| r.required.as_ref())),
            optional: names(rules.and_then(|r| r.optional.as_ref())),
            fixed: rules
                .and_then(|r| r.fixed.as_ref())
                .into_iter()
                .flatten()
                .map(|(name, value)| (name.as_str(), value))
                .collect(),
            forbidden: names(rules.and_then(|r| r.forbidden.as_ref())),
            allow_more: rules.map_or(allow_more_when_absent, |r| {
                r.additional == Some(Additional::Allow)
            }),
        };
        let mut seen = BTreeSet::new();
        if let Some(rules) = rules {
            for name in [&rules.required, &rules.optional, &rules.forbidden]
                .into_iter()
                .flatten()
                .flatten()
                .map(String::as_str)
                .chain(domain.fixed.keys().copied())
            {
                if !seen.insert(name) {
                    return Err(PolicyError::ConflictingConstraintName);
                }
            }
        }
        Ok(domain)
    }

    fn declares(&self, name: &str) -> bool {
        self.required.contains(name)
            || self.optional.contains(name)
            || self.fixed.contains_key(name)
    }

    fn permits(&self, name: &str) -> bool {
        !self.forbidden.contains(name) && (self.allow_more || self.declares(name))
    }

    fn overlaps(&self, other: &Self) -> bool {
        let required_allowed = |a: &Self, b: &Self| {
            a.required
                .iter()
                .chain(a.fixed.keys())
                .all(|name| b.permits(name))
        };
        required_allowed(self, other)
            && required_allowed(other, self)
            && self.fixed.iter().all(|(name, value)| {
                other
                    .fixed
                    .get(name)
                    .is_none_or(|other_value| value == other_value)
            })
    }
}

struct RestMatch<'a> {
    kind: &'a str,
    path: Path<'a>,
    body: Domain<'a>,
    query: Domain<'a>,
}

fn equivalent_graphql_reads(
    left: (&Kind, &GraphqlRequest),
    right: (&Kind, &GraphqlRequest),
) -> bool {
    let ((a, a_request), (b, b_request)) = (left, right);
    [a, b].into_iter().all(|kind| {
        kind.class == Class::Read && kind.approval == Approval::None && kind.ownership.is_none()
    }) && a.identity == b.identity
        && a.credential == b.credential
        && a_request.arguments == b_request.arguments
}

pub(super) fn validate_requests(rules: &RuleSet) -> Result<(), PolicyError> {
    use PolicyError::*;
    let mut rest: BTreeMap<_, Vec<RestMatch<'_>>> = BTreeMap::new();
    let mut graphql: BTreeMap<_, Vec<(&Kind, &GraphqlRequest)>> = BTreeMap::new();
    let graphql_path = Path::parse("/graphql")?;
    for kind in &rules.kinds {
        let mut declared = BTreeSet::new();
        for request in &kind.requests {
            match request {
                Request::Rest(r) => {
                    if r.method.is_empty()
                        || !r
                            .method
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                    {
                        return Err(InvalidMethod);
                    }
                    if rules.hosts.binary_search(&r.host).is_err() {
                        return Err(UndeclaredHost);
                    }
                    let path = Path::parse(&r.path)?;
                    if path.has_param(Parameter::Owner)
                        && !path.has_param(Parameter::Repo)
                        && !(kind.class == Class::Read && kind.identity == Identity::Anonymous)
                    {
                        return Err(UnboundOwner);
                    }
                    if r.host == GRAPHQL_HOST && path.overlaps(&graphql_path) {
                        return Err(ReservedGraphqlPath);
                    }
                    let body = Domain::new(r.body.as_ref(), true)?;
                    if r.body.is_some() && kind.class != Class::Read && body.allow_more {
                        return Err(OpenWriteBody);
                    }
                    if body.fixed.values().any(|v| v.is_array() || v.is_object()) {
                        return Err(InvalidBodyFixedValue);
                    }
                    let query = Domain::new(r.query.as_ref(), kind.class == Class::Read)?;
                    if query.fixed.values().any(|v| !v.is_string()) {
                        return Err(InvalidQueryFixedValue);
                    }
                    declared.extend(path.params.iter().copied());
                    declared.extend(
                        body.required
                            .iter()
                            .chain(&body.optional)
                            .chain(body.fixed.keys())
                            .copied(),
                    );
                    rest.entry((r.method.as_str(), r.host.as_str()))
                        .or_default()
                        .push(RestMatch {
                            kind: &kind.kind,
                            path,
                            body,
                            query,
                        });
                }
                Request::Graphql(g) => {
                    if !rules.hosts.iter().any(|host| host == GRAPHQL_HOST) {
                        return Err(UndeclaredHost);
                    }
                    let fields: BTreeSet<_> = g.fields.iter().map(String::as_str).collect();
                    if fields.is_empty()
                        || fields.len() != g.fields.len()
                        || !fields.iter().all(|f| graphql_name(f))
                    {
                        return Err(InvalidGraphqlFields);
                    }
                    for (path, predicate) in g.arguments.iter().flatten() {
                        if !path.split('.').all(graphql_name)
                            || (*predicate == Predicate::RepositoryInScope
                                && (path != "repository" || !fields.contains("repository")))
                        {
                            return Err(InvalidGraphqlArgumentPath);
                        }
                    }
                    let entries = graphql.entry((g.operation, fields)).or_default();
                    if entries.iter().copied().any(|prior| {
                        prior.0.kind != kind.kind && !equivalent_graphql_reads(prior, (kind, g))
                    }) {
                        return Err(RequestOverlap);
                    }
                    entries.push((kind, g));
                }
            }
        }
        if let Some(consent) = &kind.consent {
            if consent
                .fields
                .iter()
                .any(|field| !declared.contains(field.as_str()))
            {
                return Err(UndeclaredConsentField);
            }
        }
    }

    for entries in rest.values() {
        for (i, a) in entries.iter().enumerate() {
            for b in &entries[i + 1..] {
                if a.kind != b.kind
                    && a.path.overlaps(&b.path)
                    && a.body.overlaps(&b.body)
                    && a.query.overlaps(&b.query)
                {
                    return Err(RequestOverlap);
                }
            }
        }
    }
    Ok(())
}

fn graphql_name(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cases(ty: Parameter, yes: &[&str], no: &[&str]) {
        for s in yes {
            assert!(ty.matches(s), "{ty:?} should accept {s:?}");
        }
        for s in no {
            assert!(!ty.matches(s), "{ty:?} should refuse {s:?}");
        }
    }

    #[test]
    fn owner_base_and_enterprise_suffix_boundaries() {
        cases(
            Parameter::Owner,
            &[
                "0",
                "a--Z",
                "A_0",
                &"a".repeat(39),
                &format!("{}_{}", "a".repeat(39), "Z".repeat(16)),
            ],
            &[
                "",
                "-a",
                "a-",
                "A_",
                "A_a-a",
                "aa_bb_cc",
                "é",
                &"a".repeat(40),
                &format!("A_{}", "a".repeat(17)),
            ],
        );
    }

    #[test]
    fn repository_character_and_length_boundaries() {
        cases(
            Parameter::Repo,
            &["-", "A.b_0", "...", &"a".repeat(100)],
            &["", ".", "..", "é", "a/b", "a+b", &"a".repeat(101)],
        );
    }

    #[test]
    fn issue_number_character_and_value_boundaries() {
        cases(
            Parameter::Number,
            &["1", "2147483647"],
            &[
                "",
                "0",
                "01",
                "+1",
                "-1",
                "1a",
                "1.0",
                "2147483648",
                "10000000000",
            ],
        );
    }

    #[test]
    fn database_id_character_and_value_boundaries() {
        cases(
            Parameter::Id,
            &["1", "9007199254740991"],
            &[
                "",
                "0",
                "01",
                "-1",
                "1e1",
                "9007199254740992",
                "10000000000000000",
            ],
        );
    }

    #[test]
    fn sha_accepts_only_two_exact_widths_and_lowercase_hex() {
        cases(
            Parameter::Sha,
            &[&"0".repeat(40), &"f".repeat(64)],
            &[
                &"a".repeat(39),
                &"a".repeat(41),
                &"a".repeat(63),
                &"a".repeat(65),
                &"A".repeat(40),
                &"g".repeat(40),
            ],
        );
    }

    #[test]
    fn name_character_and_utf8_byte_boundaries() {
        cases(
            Parameter::Name,
            &["a", "é😀%2F", &format!("{}a", "é".repeat(127))],
            &[
                "",
                ".",
                "..",
                "a/b",
                "a\\b",
                "a\0b",
                "a\u{7f}b",
                "a\nb",
                &"é".repeat(128),
            ],
        );
    }

    #[test]
    fn template_tail_overlap_checks_one_or_more_segments_and_total_length() {
        let tail = Path::parse("/prefix/{path*}").unwrap();
        let short = "a".repeat(255);
        let longest = format!("/prefix/{short}/{short}/{short}/{short}/a");
        // 255 * 4 + 3 separators = 1023; another segment costs at least two.
        let exact = format!("/prefix/{short}/{short}/{short}/{}/a", "a".repeat(254));
        assert!(tail.overlaps(&Path::parse(&exact).unwrap()));
        assert!(!tail.overlaps(&Path::parse(&longest).unwrap()));
        assert!(!tail.overlaps(&Path::parse("/prefix").unwrap()));
        assert!(tail.overlaps(&Path::parse("/prefix/a").unwrap()));
        assert!(tail.overlaps(&Path::parse("/prefix/a/b/{ref*}").unwrap()));
        assert!(!tail.overlaps(&Path::parse(&format!("/prefix/{}", "a".repeat(256))).unwrap()));
    }

    #[test]
    fn tail_parameter_name_boundaries() {
        assert!(Path::parse("/{a*}").is_ok());
        assert!(Path::parse("/{a_1*}").is_ok());
        assert!(Path::parse(&format!("/{{{}*}}", "a".repeat(32))).is_ok());
        for bad in [
            "/{1a*}",
            "/{A*}",
            "/{a-b*}",
            "/{*}",
            &format!("/{{{}*}}", "a".repeat(33)),
        ] {
            assert!(
                matches!(Path::parse(bad), Err(PolicyError::UnknownPathParameter)),
                "{bad}"
            );
        }
    }

    #[test]
    fn template_overlap_checks_each_parameter_intersection_and_path_count() {
        for (left, right, expected) in [
            ("/x/{sha}", "/x/{owner}", false),
            ("/x/{sha}", "/x/{id}", false),
            ("/x/{sha}", "/x/{number}", false),
            ("/x/{sha}", "/x/{repo}", true),
            ("/x/{id}", "/x/{number}", true),
            ("/x/{owner}", "/x/one_org", true),
            ("/x/{number}", "/x/01", false),
            ("/x/{number}", "/x/1", true),
            ("/x/{repo}", "/x/a/b", false),
            ("/x/{name}", "/y/{name}", false),
            ("/X/{name}", "/x/{name}", false),
        ] {
            let a = Path::parse(left).unwrap();
            let b = Path::parse(right).unwrap();
            assert_eq!(a.overlaps(&b), expected, "{left}, {right}");
            assert_eq!(b.overlaps(&a), expected, "{right}, {left}");
        }
    }

    #[test]
    fn field_overlap_considers_required_fixed_forbidden_and_closed_allowlist() {
        for (a, b, overlap) in [
            (
                json!({"fixed":{"state":"open"}}),
                json!({"fixed":{"state":"closed"}}),
                false,
            ),
            (
                json!({"fixed":{"state":"closed"}}),
                json!({"forbidden":["state"],"additional":"allow"}),
                false,
            ),
            (
                json!({"required":["page"]}),
                json!({"forbidden":["page"],"additional":"allow"}),
                false,
            ),
            (
                json!({"required":["page"]}),
                json!({"optional":["sort"]}),
                false,
            ),
            (
                json!({"required":["page"]}),
                json!({"optional":["page"]}),
                true,
            ),
            (
                json!({"optional":["sort"]}),
                json!({"optional":["page"]}),
                true,
            ),
            (
                json!({"fixed":{"page":"2"}}),
                json!({"fixed":{"page":"2"}}),
                true,
            ),
        ] {
            let a = serde_json::from_value::<Constraints>(a).unwrap();
            let b = serde_json::from_value::<Constraints>(b).unwrap();
            let a = Domain::new(Some(&a), false).unwrap();
            let b = Domain::new(Some(&b), false).unwrap();
            assert_eq!(a.overlaps(&b), overlap);
            assert_eq!(b.overlaps(&a), overlap);
        }
    }

    #[test]
    fn default_query_domains_differ_for_read_and_write() {
        let rules = serde_json::from_value::<Constraints>(json!({"required":["page"]})).unwrap();
        let named = Domain::new(Some(&rules), false).unwrap();
        assert!(named.overlaps(&Domain::new(None, true).unwrap()));
        assert!(!named.overlaps(&Domain::new(None, false).unwrap()));
    }
}
