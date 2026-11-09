#!/usr/bin/env python3
"""The only writer of the multi-host secret contract corpus and its SHA256SUMS.

No parser, matcher, PSL evaluator or encryption implementation lives here: outcomes
are explicit contract examples. Byte encoders cover only JCS and push_field frames.
Run without arguments to regenerate, or with --check to verify without writing.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "crates/credentials-core/tests/vectors/multi-host"
PSL_SNAPSHOT = {
    "url": "https://raw.githubusercontent.com/publicsuffix/list/"
           "ab73a956765706dc3f42dbac5c7e48df2297e1ac/public_suffix_list.dat",
    "date": "2026-11-09",
    "sha256": "7bd9c5479d1ac1a4118b982a3a05b65719e3215cb873474f9799af6222006da4",
}
MEMBER = "fed-computer:" + "2" * 32
ASKER = "fed-computer:" + "1" * 32
REQUEST = "01HF7YAT000000000000000001"
INCARNATION = "00000000000000000000000000000149"
LOCATION = "header:X-Api-Key"
API = "agent_api_key"
LOGIN = "site_login"
USE_V3 = "ck-secret-use-statement/v3"
FLOW_V3 = "ck-secret-flow-statement/v3"
EIGHT_RULES = [{"host": f"api{i}.x.test", "path_prefix": "/v1"} for i in range(8)]
FOUR_ORIGINS = [f"https://login{i}.x.test" for i in range(4)]


def jcs(value):
    """RFC 8785 bytes for the corpus's JSON subset (no floats or unsafe integers).

    Reject unsupported numbers instead of silently using Python's non-JCS float
    formatting. Object keys sort by UTF-16 code units, not Python code points.
    """
    def encode(item):
        if item is None:
            return "null"
        if isinstance(item, bool):
            return "true" if item else "false"
        if isinstance(item, int) and abs(item) <= 2**53 - 1:
            return str(item)
        if isinstance(item, str):
            item.encode("utf-8")  # Reject lone surrogates, which JCS forbids.
            return json.dumps(item, ensure_ascii=False)
        if isinstance(item, list):
            return "[" + ",".join(encode(part) for part in item) + "]"
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            keys = sorted(item, key=lambda key: key.encode("utf-16be"))
            return "{" + ",".join(encode(key) + ":" + encode(item[key]) for key in keys) + "}"
        raise ValueError(f"not in the corpus JCS subset: {type(item).__name__}")

    return encode(value).encode("utf-8")


def frames(*fields):
    """agent_secret::push_field: unsigned u64 little-endian byte length, then bytes."""
    encoded = [field.encode("utf-8") if isinstance(field, str) else field for field in fields]
    return b"".join(struct.pack("<Q", len(field)) + field for field in encoded)


def emitted(scope):
    result = deepcopy(scope)
    if "rules" in result:
        result["rules"] = sorted(
            [{"host": rule["host"], "path_prefix": rule.get("path_prefix", "")}
             for rule in result["rules"]],
            key=lambda rule: (rule["host"].encode(), rule["path_prefix"].encode()))
    if "origins" in result:
        result["origins"] = sorted(result["origins"], key=lambda origin: origin.encode())
    return result


def scope_fields(kind, scope):
    if "rules" in scope:
        fields = [str(len(scope["rules"]))]
        for rule in scope["rules"]:
            fields.extend([rule["host"], rule.get("path_prefix", "")])
        return fields + [scope["location"]]
    if "origins" in scope:
        return [str(len(scope["origins"]))] + scope["origins"]
    if kind == API:
        return [scope["host"], scope.get("path_prefix", ""), scope["location"]]
    return [scope["origin"]]


def material_fields(kind, material):
    if kind == API:
        return [bytes.fromhex(material["api_key_hex"])]
    return [material["username"], material["password"], material.get("otpauth", "")]


def deposit_bytes(params, material):
    kind = params["kind"]
    extended = "rules" in params or "origins" in params
    version = 2 if extended else 1
    aad = frames(f"ck-secret-deposit-aad/v{version}", params["deposit_id"],
                 params["member_id"], params["name"], kind, *scope_fields(kind, params))
    body = frames(f"ck-secret-sealed-body/v{version}", kind,
                  *scope_fields(kind, emitted(params)), *material_fields(kind, material))
    plaintext = frames("ck-secret-deposit-plaintext/v1", *material_fields(kind, material))
    return {"aad_hex": aad.hex(), "sealed_body_hex": body.hex(),
            "plaintext_hex": plaintext.hex(), "record_version": 1}


def api_target(host="a.x.test", path="/", scheme="https", port=443):
    return {"scheme": scheme, "host": host, "port": port, "path": path}


def scope_corpus():
    cases = []

    def add(name, scope, target=None, expect: str | dict[str, str] = "match", kind=API, form="input"):
        row = {"case": name, "form": form, "kind": kind, "scope": scope, "expect": expect}
        if target is not None:
            row["target"] = target
        cases.append(row)

    def refuse(name, scope, code="invalid_params", kind=API, form="input"):
        add(name, scope, expect={"scope_refused": code}, kind=kind, form=form)

    wildcard = {"rules": [{"host": "*.x.test"}]}
    for name, host, expect in [("child", "a.x.test", "match"),
                               ("base", "x.test", "no_match"),
                               ("grandchild", "a.b.x.test", "no_match"),
                               ("suffix-lookalike", "ax.test", "no_match")]:
        add("wildcard-" + name, wildcard, api_target(host), expect)
    add("login-target-is-not-api-key", wildcard, {"origin": "https://a.x.test"}, "no_match")
    add("eight-rules", {"rules": EIGHT_RULES}, api_target("api7.x.test", "/v1/x"))
    refuse("nine-rules", {"rules": EIGHT_RULES + [{"host": "api8.x.test"}]}, "limit_exceeded")
    add("four-origins", {"origins": FOUR_ORIGINS}, {"origin": FOUR_ORIGINS[-1]}, kind=LOGIN)
    add("api-target-is-not-login", {"origins": FOUR_ORIGINS}, api_target(), "no_match", LOGIN)
    add("stored-origins-as-sent", {"origins": ["https://x.test:443", "https://y.test"]},
        {"origin": "https://x.test"}, kind=LOGIN, form="stored")
    refuse("five-origins", {"origins": FOUR_ORIGINS + ["https://login4.x.test"]},
           "limit_exceeded", LOGIN)
    for base, expect in [("com", False), ("github.io", False), ("xn--55qx5d.cn", False),
                         ("foo.github.io", True), ("x.test", True),
                         ("test", False), ("a.ck", False), ("www.ck", True)]:
        scope = {"rules": [{"host": "*." + base}]}
        if expect:
            add("psl-" + base, scope, api_target("a." + base))
        else:
            refuse("psl-" + base, scope)
    add("stored-private-suffix-still-usable", {"rules": [{"host": "*.github.io", "path_prefix": ""}]},
        api_target("a.github.io"), form="stored")
    add("stored-empty-prefix-is-absent", {"rules": [{"host": "*.x.test", "path_prefix": ""}]},
        api_target(), form="stored")
    refuse("stored-exact-singleton", {"rules": [{"host": "a.x.test", "path_prefix": ""}]},
           form="stored")
    refuse("stored-duplicate-rules", {"rules": [{"host": "*.x.test", "path_prefix": ""}] * 2},
           form="stored")
    refuse("exact-singleton", {"rules": [{"host": "a.x.test"}]})
    refuse("origin-singleton", {"origins": ["https://x.test"]}, kind=LOGIN)
    refuse("duplicate-rules", {"rules": [{"host": "*.x.test"}] * 2})
    refuse("duplicate-canonical-origins", {"origins": ["https://x.test", "https://x.test:443"]}, kind=LOGIN)
    add("overlapping-wildcard-exact", {"rules": [{"host": "*.x.test"}, {"host": "a.x.test"}]}, api_target())
    add("overlapping-prefixes", {"rules": [{"host": "a.x.test"},
                                           {"host": "a.x.test", "path_prefix": "/v1"}]}, api_target())
    for path, expect in [("/v1/*", "match"), ("/v1/*/x", "match"), ("/v1/items", "no_match")]:
        add("literal-star-" + path, {"rules": [{"host": "*.x.test", "path_prefix": "/v1/*"}]},
            api_target(path=path), expect)
    legacy = {"host": "a.x.test", "path_prefix": "/repos/a"}
    for name, target, expect in [
            ("http", api_target(path="/repos/a", scheme="http"), "no_match"),
            ("port", api_target(path="/repos/a", port=444), "no_match"),
            ("other-host", api_target("b.x.test", "/repos/a"), "no_match"),
            ("segment-boundary", api_target(path="/repos/ab"), "no_match"),
            ("exact-prefix", api_target(path="/repos/a"), "match"),
            ("trailing-slash", api_target(path="/repos/a/"), "match"),
            ("child", api_target(path="/repos/a/x"), "match")]:
        add("legacy-" + name, legacy, target, expect)
    add("legacy-no-percent-decoding", {"host": "a.x.test", "path_prefix": "/repos/~"},
        api_target(path="/repos/%7E"), "no_match")
    for path in ["/", "/x/y"]:
        add("legacy-no-prefix-" + path, {"host": "a.x.test"}, api_target(path=path))
    for path, expect in [("/v1/*", "match"), ("/v1/*/x", "match"), ("/v1/items", "no_match")]:
        add("legacy-literal-star-" + path, {"host": "a.x.test", "path_prefix": "/v1/*"},
            api_target(path=path), expect)
    for origin, expect in [("https://x.test:443", "match"), ("http://x.test", "no_match"),
                           ("https://y.test", "no_match"), ("https://x.test:444", "no_match")]:
        add("legacy-login-" + origin, {"origin": "https://x.test"}, {"origin": origin}, expect, LOGIN)
    add("legacy-alabel", {"host": "xn--55qx5d.cn"}, api_target("xn--55qx5d.cn"))
    for name, host in [("uppercase", "A.x.test"), ("trailing-dot", "a.x.test."),
                       ("ipv4", "127.0.0.1"), ("ipv6", "::1"), ("empty-label", "a..test"),
                       ("leading-hyphen", "-a.test"), ("trailing-hyphen", "a-.test"),
                       ("unicode", "公司.cn"), ("empty", ""),
                       ("wildcard", "*.x.test")]:
        refuse("legacy-host-" + name, {"host": host})
    for host in ["*", "*.", "a.*.b", "*a.b", "*.*.b"]:
        refuse("misplaced-wildcard-" + host, {"rules": [{"host": host}]})
    # Long labels remain legal under the legacy grammar; only total host bytes are capped.
    add("host-253-bytes", {"host": "a" * 248 + ".test"}, api_target("a" * 248 + ".test"))
    refuse("host-254-bytes", {"host": "a" * 249 + ".test"}, "limit_exceeded")
    refuse("host-grammar-before-cap", {"host": "A" + "a" * 248 + ".test"})
    add("wildcard-host-253-bytes", {"rules": [{"host": "*." + "a" * 246 + ".test"}]},
        api_target("b." + "a" * 246 + ".test"))
    refuse("wildcard-host-254-bytes", {"rules": [{"host": "*." + "a" * 247 + ".test"}]}, "limit_exceeded")
    for prefix in ["/", "/repos/a/", "", "relative", "/a//b", "/a/../b", "/%2F", "/%ZZ"]:
        refuse("legacy-prefix-" + repr(prefix), {"host": "a.x.test", "path_prefix": prefix})
    refuse("input-empty-prefix", {"rules": [{"host": "*.x.test", "path_prefix": ""}]})
    add("prefix-1024-bytes", {"host": "a.x.test", "path_prefix": "/" + "a" * 1023},
        api_target(path="/" + "a" * 1023))
    refuse("prefix-1025-bytes", {"host": "a.x.test", "path_prefix": "/" + "a" * 1024}, "limit_exceeded")
    refuse("prefix-grammar-before-cap", {"host": "a.x.test", "path_prefix": "/" + "a" * 1023 + "/"})
    for name, origin in [("wildcard", "https://*.x.test"), ("http", "http://x.test"),
                         ("path", "https://x.test/"), ("port", "https://x.test:444")]:
        refuse("login-origin-" + name, {"origins": [origin, "https://y.test"]}, kind=LOGIN)
    # These pairs intentionally have two faults to pin the first failing check.
    refuse("precedence-count-before-entry", {"rules": [{"host": "BAD"}] * 9}, "limit_exceeded")
    refuse("precedence-host-cap-before-prefix", {"host": "a" * 249 + ".test", "path_prefix": ""}, "limit_exceeded")
    refuse("precedence-sent-entry-order", {"rules": [{"host": "a.x.test", "path_prefix": "/" + "a" * 1024},
                                                     {"host": "BAD"}]}, "limit_exceeded")
    refuse("precedence-entry-before-singleton", {"rules": [{"host": "a" * 249 + ".test"}]}, "limit_exceeded")
    refuse("precedence-origin-singleton-before-entry", {"origins": ["https://" + "a" * 249 + ".test"]}, kind=LOGIN)
    refuse("precedence-origin-count-before-entry", {"origins": ["not-an-origin"] * 5}, "limit_exceeded", LOGIN)
    return {"v": "ck-secret-scope-match/v1", "psl_snapshot": PSL_SNAPSHOT, "cases": cases}


def statement_sample(statement):
    encoded = jcs(statement)
    return {"statement": statement, "statement_jcs_hex": encoded.hex(),
            "statement_sha256": hashlib.sha256(encoded).hexdigest()}


def statement_object(kind, scope, forwarded=False, flow=False):
    statement = {
        "v": FLOW_V3 if flow else USE_V3, "request_id": REQUEST, "member_id": MEMBER,
        "secret": {"name": "key" if kind == API else "login", "kind": kind,
                   "incarnation": INCARNATION},
        "use": emitted(scope), "request_expires_at_ms": 1700000600000,
    }
    if forwarded:
        statement["asking_member_id"] = ASKER
    if flow:
        statement["flow"] = {"flow_id": "daily-fetch", "version": 7,
                             "code_hash": "0123456789abcdef" * 4, "install_id": "install-A"}
        statement["durations"] = ["version"]
        if kind == API:
            statement["use"]["methods"] = ["GET", "POST"]
    else:
        statement.update({"agent_id": "agent-A", "coverage": "scope",
                          "scope": {"owner": "reserved:prefrontal-core", "kind": "head", "ref": "H", "epoch": 7},
                          "durations": ["once", "hour", "session", "permanent"]})
    return statement


def statement_corpus(flow=False):
    cases = []
    scopes = [("eight-rules", API, {"rules": EIGHT_RULES, "location": LOCATION}),
              ("lone-wildcard-no-prefix", API, {"rules": [{"host": "*.x.test"}], "location": LOCATION}),
              ("two-origins", LOGIN, {"origins": ["https://x.test", "https://y.test:443"]}),
              ("four-origins", LOGIN, {"origins": FOUR_ORIGINS})]
    for label, kind, scope in scopes:
        for forwarded in [False, True]:
            statement = statement_object(kind, scope, forwarded, flow)
            operation = "secret.request_flow_approval" if flow else "secret.use"
            if forwarded:
                operation = "federation.secret_request_flow_approval" if flow else "federation.secret_use"
            cases.append({
                "case": ("forwarded-" if forwarded else "local-") + label,
                "operation": operation,
                "setup": {"stored_scope": emitted(scope), "kind": kind,
                          "pending_asking_member_id": ASKER if forwarded else "",
                          "live_grant": False},
                "expect": {"status": "approval_required"},
                **statement_sample(statement),
            })
    for forwarded, mutation in [(False, "added"), (True, "missing"), (True, "different")]:
        scope = {"rules": [{"host": "*.x.test"}], "location": LOCATION}
        statement = statement_object(API, scope, forwarded, flow)
        if mutation == "missing":
            del statement["asking_member_id"]
        else:
            statement["asking_member_id"] = "fed-computer:" + "3" * 32
        cases.append({"case": "asker-" + mutation, "operation": "secret.approve",
                      "setup": {"kind": API, "stored_scope": emitted(scope),
                                "pending_asking_member_id": ASKER if forwarded else "",
                                "envelope_signature_valid": True, "envelope_digest_matches_statement": True},
                      "expect": {"code": "approval_invalid"}, **statement_sample(statement)})
    if flow:
        for tag in [USE_V3, FLOW_V3]:
            for forwarded in [False, True]:
                cases.append({"case": ("forwarded-" if forwarded else "local-") + "flow-id-" + tag,
                              "operation": "federation.secret_request_flow_approval" if forwarded else "secret.request_flow_approval",
                              "setup": {"kind": API, "stored_scope": emitted(scopes[1][2]),
                                        "asking_member_id": ASKER if forwarded else ""},
                              "params": {"name": "key", "flow": {
                                  "flow_id": tag, "version": 7, "code_hash": "0123456789abcdef" * 4,
                                  "install_id": "install-A"}, "target": api_target(), "methods": ["GET"]},
                              "expect": {"code": "invalid_params"}})
    return {"v": "ck-secret-flow-approval/v3" if flow else "ck-secret-approval/v3", "cases": cases}


def deposit_corpus():
    cases = []
    samples = [
        ("noncanonical-sent-order", API,
         {"rules": [{"host": "z.x.test", "path_prefix": "/v1"}, {"host": "a.x.test"}], "location": LOCATION}),
        ("eight-rules", API, {"rules": EIGHT_RULES, "location": LOCATION}),
        ("lone-wildcard", API, {"rules": [{"host": "*.x.test"}], "location": LOCATION}),
        ("four-origins", LOGIN, {"origins": list(reversed(FOUR_ORIGINS))}),
        ("two-origins", LOGIN, {"origins": ["https://y.test:443", "https://x.test"]}),
    ]
    for label, kind, scope in samples:
        material = ({"api_key_hex": b"ckios-fixed-api-key".hex()} if kind == API else
                    {"username": "test-user", "password": "test-only-password"})
        params = {"deposit_id": REQUEST, "member_id": MEMBER,
                  "name": "key" if kind == API else "login", "kind": kind, **scope}
        cases.append({"case": label, "operation": "secret.deposit",
                      "setup": {"secret.multi_host": "true", "name_exists": False, "tombstone": None},
                      "params": params, "material": material, **deposit_bytes(params, material),
                      "expect": {"status": "stored", "stored_scope": emitted(scope), "statement_v": USE_V3}})
    lone = deepcopy(cases[2]["params"])
    no_writes = {"agent_secrets": 0, "tombstones": 0, "secret_store_audits": 0}
    for gate in ["false", "unreadable", None]:
        for operation in ["secret.deposit", "admin.secret_put"]:
            cases.append({"case": operation + "-gate-" + str(gate), "operation": operation,
                          "setup": {"secret.multi_host": gate, "home_role": "single", "tombstone": None},
                          "params": lone if operation == "secret.deposit" else {
                              "v": 2, "name": "key", "kind": API, "rules": lone["rules"], "location": LOCATION},
                          "expect": {"error": {"code": "secret_multi_host_disabled", "class": "permanent"},
                                     "writes": no_writes}})
            if operation == "secret.deposit":
                cases[-1].update({"material": cases[2]["material"], **deposit_bytes(lone, cases[2]["material"])})
    cases.append({"case": "exact-replay-before-gate", "operation": "secret.deposit",
                  "setup": {"secret.multi_host": "false", "tombstone": "same-deposit-bytes-and-live-incarnation"},
                  "params": lone, "material": cases[2]["material"],
                  **deposit_bytes(lone, cases[2]["material"]), "expect": {"status": "already_stored"}})
    reordered = deepcopy(cases[0]["params"])
    reordered["rules"].reverse()
    cases.append({"case": "reordered-replay-conflicts", "operation": "secret.deposit",
                  "setup": {"secret.multi_host": "false", "tombstone_from_case": "noncanonical-sent-order"},
                  "params": reordered, "material": cases[0]["material"], "expect": {"code": "deposit_conflict"},
                  **deposit_bytes(reordered, cases[0]["material"])})
    for gate in ["false", "unreadable", None]:
        params = {"deposit_id": REQUEST, "member_id": MEMBER, "name": "key", "kind": API,
                  "host": "x.test", "path_prefix": "/repos/a", "location": LOCATION}
        material = {"api_key_hex": b"ckios-fixed-api-key".hex()}
        cases.append({"case": "legacy-ignores-gate-" + str(gate), "operation": "secret.deposit",
                      "setup": {"secret.multi_host": gate, "name_exists": False, "tombstone": None},
                      "params": params, "material": material, **deposit_bytes(params, material),
                      "expect": {"status": "stored", "statement_v": "ck-secret-use-statement/v1"}})
    shapes = [
        ("rules-not-array", {"rules": {}}, "invalid_params"),
        ("rules-empty", {"rules": []}, "invalid_params"),
        ("rule-not-object", {"rules": ["*.x.test"]}, "invalid_params"),
        ("rule-missing-host", {"rules": [{"path_prefix": "/v1"}]}, "invalid_params"),
        ("rule-unknown-key", {"rules": [{"host": "*.x.test", "extra": "x"}]}, "invalid_params"),
        ("rule-host-not-string", {"rules": [{"host": 7}]}, "invalid_params"),
        ("rule-prefix-not-string", {"rules": [{"host": "*.x.test", "path_prefix": None}]}, "invalid_params"),
        ("rules-with-host", {"rules": [{"host": "*.x.test"}], "host": "x.test"}, "invalid_params"),
        ("rules-with-null-host", {"rules": [{"host": "*.x.test"}], "host": None}, "invalid_params"),
        ("rules-with-prefix", {"rules": [{"host": "*.x.test"}], "path_prefix": "/v1"}, "invalid_params"),
        ("shape-before-count", {"rules": EIGHT_RULES + [{"host": "api8.x.test"}], "host": "x.test"}, "invalid_params"),
        ("nine-rules-with-invalid-location", {"rules": EIGHT_RULES + [{"host": "a.test"}], "location": "bad"}, "limit_exceeded"),
        ("invalid-location", {"rules": [{"host": "*.x.test"}], "location": "header:Host"}, "invalid_params"),
    ]
    for label, scope, code in shapes:
        cases.append({"case": label, "operation": "secret.deposit",
                      "setup": {"secret.multi_host": "true"},
                      "params": {"deposit_id": REQUEST, "member_id": MEMBER, "name": "key", "kind": API,
                                 "location": LOCATION, **scope}, "expect": {"code": code}})
    for label, scope in [
            ("origins-not-array", {"origins": "https://x.test"}), ("origins-empty", {"origins": []}),
            ("origin-not-string", {"origins": [7, "https://x.test"]}),
            ("origins-with-origin", {"origins": FOUR_ORIGINS, "origin": "https://x.test"})]:
        cases.append({"case": label, "operation": "secret.deposit", "setup": {"secret.multi_host": "true"},
                      "params": {"deposit_id": REQUEST, "member_id": MEMBER, "name": "login", "kind": LOGIN, **scope},
                      "expect": {"code": "invalid_params"}})
    cases.append({"case": "admin-null-legacy-fields-are-absent", "operation": "admin.secret_put",
                  "setup": {"secret.multi_host": "true", "home_role": "single", "name_exists": False},
                  "params": {"v": 2, "kind": API, "name": "key", "host": None, "path_prefix": None,
                             "origin": None, "rules": lone["rules"], "location": LOCATION},
                  "expect": {"stored_scope": emitted({"rules": lone["rules"], "location": LOCATION})}})
    for extended, body_version in [(True, 1), (False, 2)]:
        cases.append({"case": f"row-extended-{extended}-body-v{body_version}", "operation": "secret.use",
                      "setup": {"scope_json_nonnull": extended, "sealed_body_version": body_version,
                                "live_grant": True}, "expect": {"code": "sealed_scope"}})
    return {"v": "ck-secret-deposit/v2", "cases": cases}


def list_corpus():
    cases = []
    scopes = [(API, {"rules": [{"host": "b.x.test", "path_prefix": "/v1"}, {"host": "a.x.test"}],
                     "location": LOCATION}),
              (LOGIN, {"origins": ["https://y.test:443", "https://x.test"]})]
    for kind, scope in scopes:
        name = "key" if kind == API else "login"
        stored = emitted(scope)
        secret = {"name": name, "kind": kind, "incarnation": INCARNATION, "state": "active",
                  **stored, "grants": [], "flow_grants": []}
        reply = {"secrets": [secret]}
        cases.append({"case": "list-" + kind, "operation": "secret.list", "params": {},
                      "setup": {"kind": kind, "name": name, "stored_scope": stored},
                      "expect": reply})
        entries = ([rule["host"] + rule["path_prefix"] for rule in stored["rules"]]
                   if kind == API else stored["origins"])
        label = ("use " if kind == API else "fill ") + name + " on " + ", ".join(entries)
        for grant_kind in ["agent", "flow"]:
            cases.append({"case": "permissions-" + grant_kind + "-" + kind,
                          "operation": "permissions.list", "params": {},
                          "setup": {"kind": kind, "name": name, "stored_scope": stored, "grant_kind": grant_kind},
                          "expect": {"scope_label": label}})
        tokens = (["rule=" + entry for entry in entries] + ["location=" + LOCATION]
                  if kind == API else ["origin=" + entry for entry in entries])
        cases.append({"case": "operator-list-" + kind, "operation": "ck auth secret list",
                      "setup": {"kind": kind, "name": name, "stored_scope": stored},
                      "expect": {"line": f"{name} {kind} active " + " ".join(tokens)}})
    corrupt = {"kind": API, "name": "key", "scope_json": "not-json"}
    for operation, code in [("secret.list", "store_error"), ("permissions.list", "store_error"),
                             ("secret.use", "sealed_scope")]:
        cases.append({"case": "corrupt-" + operation, "operation": operation,
                      "setup": corrupt, "expect": {"code": code}})
    cases.append({"case": "corrupt-operator-list", "operation": "ck auth secret list", "setup": corrupt,
                  "expect": {"line": "key agent_api_key active scope=unreadable"}})
    return {"v": "ck-secret-list/v2", "cases": cases}


def documents():
    return {"secret-scope-match-v1.json": scope_corpus(),
            "secret-approval-v3.json": statement_corpus(),
            "secret-flow-approval-v3.json": statement_corpus(flow=True),
            "secret-deposit-v2.json": deposit_corpus(),
            "secret-list-v2.json": list_corpus()}


def render():
    files = {name: (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
             for name, value in documents().items()}
    files["SHA256SUMS"] = "".join(
        hashlib.sha256(files[name]).hexdigest() + "  " + name + "\n" for name in sorted(files)).encode("ascii")
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare all six files without writing")
    args = parser.parse_args()
    files = render()
    if args.check:
        mismatched = [name for name, data in files.items()
                      if not (OUTPUT / name).is_file() or (OUTPUT / name).read_bytes() != data]
        unexpected = sorted(path.name for path in OUTPUT.iterdir() if path.name not in files) if OUTPUT.exists() else []
        if mismatched or unexpected:
            parser.exit(1, f"multi-host corpus differs: {mismatched}; unexpected: {unexpected}\n")
        print(f"checked {len(files)} byte-identical multi-host files")
    else:
        OUTPUT.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            (OUTPUT / name).write_bytes(data)
        print(f"generated {len(files)} multi-host files")


if __name__ == "__main__":
    main()
