//! Secret-bearing buffers that scrub themselves and cannot be printed.
//!
//! # Why this type exists rather than a bare `Zeroizing<String>`
//!
//! Three properties are needed and `Zeroizing` supplies exactly one of them:
//!
//! | property | `Zeroizing<String>` | [`Secret`] |
//! |---|---|---|
//! | scrubbed on drop | yes | yes |
//! | serialises byte-identically | yes (`serde` feature) | yes |
//! | cannot be printed in the clear | **no** — `Debug` delegates | yes |
//!
//! That third row is the reason for the newtype. `Zeroizing` derives `Debug` from
//! its inner type, so a `{:?}` on a wrapped token prints the token — which would
//! quietly undo the redacted-`Debug` work that closed the first half of this
//! hazard. A type that is unprintable BY CONSTRUCTION cannot be un-redacted by
//! someone adding a derive in a hurry.
//!
//! # What it does not do, stated so nobody reads more into it
//!
//! A [`Secret`] scrubs THE BUFFER IT OWNS. It cannot reach a copy someone made
//! with [`Secret::expose`] and then stored elsewhere:
//!
//! ```ignore
//! let leaked = cred.access_token.expose().to_string(); // NOT scrubbed
//! ```
//!
//! That is why `expose` is a named method rather than a `Deref`. `Deref` would
//! make every read invisible and this type would become decoration: the audit
//! question "where does secret material leave its scrubbed buffer" would have no
//! mechanical answer. With `expose`, the answer is one grep, forever.
//!
//! So the rule at a call site is: pass `&Secret` where you can, call `expose()`
//! as late as possible, and never bind its result to something that outlives the
//! statement.
//!
//! # Threat model, because "zeroize" attracts more credit than it earns
//!
//! This is defence in depth against memory DISCLOSURE after the value is dead —
//! a core dump, a swap page, a heap that gets reused and read. It does nothing
//! against an attacker who can read live process memory at the moment of use, and
//! it does not make the process safe to debug. The vault's real boundaries are
//! elsewhere (encryption at rest, the master-key gate, capability handles); this
//! narrows the window in which a freed buffer still reads as a credential.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// A secret-bearing buffer: scrubbed on drop, transparent on the wire, and
/// unprintable.
///
/// `T` is the owned buffer type — `String` for tokens, `Vec<u8>` for opaque
/// payloads. Both are [`Zeroize`], which is what makes the scrub real rather than
/// nominal.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T: Zeroize + Clone>(Zeroizing<T>);

impl<T: Zeroize + Clone> Secret<T> {
    /// Take ownership of `value`, scrubbing it when this is dropped.
    ///
    /// The argument is moved rather than borrowed on purpose: a constructor that
    /// copied from a borrow would leave the caller's original unscrubbed, which is
    /// the exact defect this type exists to remove.
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the secret for use.
    ///
    /// NAMED, NOT A `Deref` IMPL. Every read of secret material is meant to be a
    /// visible act that a future audit can enumerate — `grep -rn 'expose()'` is
    /// the whole audit, and a `Deref` would make that list empty while the reads
    /// carried on.
    ///
    /// Use the borrow and drop it. Binding the result into an owned `String` or
    /// `Vec` creates a copy this type cannot reach.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume this and yield the inner buffer, still wrapped so it is scrubbed
    /// when the caller is done with it.
    ///
    /// The wrapper is deliberately retained. Returning a bare `T` here would be a
    /// silent hole in the middle of the type whose whole purpose is that ownership
    /// implies scrubbing.
    pub fn into_inner(self) -> Zeroizing<T> {
        self.0
    }
}

/// Unprintable by construction.
///
/// This is the property that a bare `Zeroizing` does not have, and the reason the
/// newtype exists. Note it renders NO length either: a length is a real oracle on
/// short or structured secrets, and a debug line is exactly where someone would
/// read one without thinking about it.
impl<T: Zeroize + Clone> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Equality is by VALUE and is NOT constant-time.
///
/// Kept because the vault compares credentials structurally in tests and in
/// version checks, never as an authentication step. Authentication comparisons in
/// this crate use dedicated constant-time paths (the admin MAC verify), and any
/// future one must do the same rather than reaching for this.
impl<T: Zeroize + Clone + PartialEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl<T: Zeroize + Clone + Eq> Eq for Secret<T> {}

impl<T: Zeroize + Clone> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

/// A secret string — an access or refresh token.
pub type SecretString = Secret<String>;

/// A secret byte buffer — an opaque credential payload.
pub type SecretBytes = Secret<Vec<u8>>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The three properties, each asserted, because two of them are silent when
    /// broken: a serde change corrupts records at rest, and a `Debug` change leaks
    /// into logs. Only the scrub is hard to observe from outside.
    #[test]
    fn a_secret_is_unprintable_and_serialises_transparently() {
        let s = SecretString::new("sk-SECRET-TOKEN".to_string());

        // 1. Unprintable. Both the value and any hint of its shape.
        let rendered = format!("{s:?}");
        assert_eq!(rendered, "<redacted>");
        assert!(
            !rendered.contains("sk-SECRET"),
            "Debug rendered the secret: {rendered}"
        );
        assert!(
            !rendered.contains("15"),
            "Debug rendered the length, which is an oracle on short secrets: {rendered}"
        );

        // 2. Transparent on the wire: a wrapped field must serialise EXACTLY as the
        // bare one did, or every sealed record in the vault becomes unreadable.
        let wrapped = serde_json::to_string(&s).expect("serialize");
        let bare = serde_json::to_string("sk-SECRET-TOKEN").expect("serialize");
        assert_eq!(
            wrapped, bare,
            "the wrapper changed the wire form; sealed records would not load"
        );

        // 3. And the reverse: bytes written before the wrapper existed must load
        // into it. This is what makes the change migration-free.
        let back: SecretString = serde_json::from_str(&bare).expect("deserialize");
        assert_eq!(back.expose(), "sk-SECRET-TOKEN");
    }

    /// Bytes behave identically, and the payload case is the one that carries
    /// non-UTF8 material.
    #[test]
    fn secret_bytes_round_trip_through_the_same_wire_form() {
        let raw = vec![0u8, 159, 146, 150, 255];
        let s = SecretBytes::new(raw.clone());
        let wrapped = serde_json::to_string(&s).expect("serialize");
        let bare = serde_json::to_string(&raw).expect("serialize");
        assert_eq!(wrapped, bare);
        assert_eq!(format!("{s:?}"), "<redacted>");
    }

    /// Equality is by value, so version checks and test fixtures keep working.
    #[test]
    fn equality_is_by_value() {
        let a = SecretString::new("same".to_string());
        let b = SecretString::new("same".to_string());
        let c = SecretString::new("different".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
