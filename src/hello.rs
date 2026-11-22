//! The signed link introduction carried in aoNetwork's opaque `app_hello`.
//!
//! A [`MeshHello`] is how a link peer learns who the other end is before
//! any packet flows. It carries the two public keys verification needs,
//! so the verified [`NodeId`] is derived, never
//! trusted, and it fits aoNetwork's 256-byte `app_hello` limit with
//! room to spare (ADR-0004):
//!
//! ```text
//! Offset  Size  Field
//! 0       16    node_id         claimed; must equal the derivation below
//! 16       8    card_hash       identity-card announcement hash, opaque
//! 24       1    proto           mesh format version the sender speaks
//! 25       4    caps            feature bits the sender sets (big-endian)
//! 29       4    store_digest    store summary digest, opaque
//! 33      32    signing_pk      Ed25519 verification key
//! 65      32    agreement_pk    X25519 key; with signing_pk derives node_id
//! 97      64    signature       over bytes 0..97 under `HELLO_DOMAIN`
//! ```
//!
//! Every field is fixed-width, so decoding is bounds-checked slicing and
//! encoding cannot normalise anything: `decode(encode(h)) == h` holds for
//! any bit pattern, and verification over the re-encoded body therefore
//! covers exactly the received bytes. The signature sits after the range
//! it covers, like the packet signature, so the covered range is one
//! contiguous prefix.
//!
//! Verification is [`ao_idents::verify_signing_pk`] under
//! [`HELLO_DOMAIN`] (registered in aoIdents ADR-0001), followed by
//! `compute_node_id` over the two keys, which must reproduce the claimed
//! `node_id`. Proof of key control is not proof of a real-world
//! identity: cards and directories bind names later; the mesh treats
//! every neighbour as hostile either way.

use ao_idents::{IdentError, Identity, NodeId, Signature, compute_node_id, verify_signing_pk};

/// Signature domain for the signed body (aoIdents ADR-0001 registry).
pub const HELLO_DOMAIN: &str = "aoheyra/mesh/v1/hello";

/// The mesh format version this build speaks.
pub const PROTO: u8 = 1;

/// The oldest version a link may fall back to; below this there is no
/// common language and the introduction fails.
pub const MIN_PROTO: u8 = 1;

/// Feature bits this build advertises by default (ADR-0001).
///
/// Hop encryption is deliberately absent: only the host can drive the
/// handshake, so a host opts in with [`crate::MeshConfig::hop_enabled`]
/// and [`MeshHello::sign_with_hop`]. A link that does not opt in stays
/// cleartext even when both peers run this build.
///
/// Bit 0 advertises MSH-14's anti-entropy sync frames. Bit 1 advertises
/// MSH-15's range reconciliation. Bit 2 advertises MSH-16's bounded spray
/// envelope. Bit 3 advertises MSH-17's signed receipt envelope. Bit 4
/// advertises MSH-19's signed presence announcements. A peer that lacks a
/// bit keeps the earlier forwarding path; a peer with only bit 0 gets the
/// MSH-14 summary exchange. Every bit needs an ADR entry.
pub const CAP_SYNC_V1: u32 = 1 << 0;
/// Capability bit for MSH-15 range-based set reconciliation.
pub const CAP_SYNC_V2: u32 = 1 << 1;
/// Capability bit for MSH-16 binary spray copy tickets.
pub const CAP_SPRAY_V1: u32 = 1 << 2;
/// Capability bit for MSH-17 signed delivery receipts and immunity gossip.
pub const CAP_RECEIPT_V1: u32 = 1 << 3;
/// Capability bit for MSH-19 signed presence announcements.
pub const CAP_PRESENCE_V1: u32 = 1 << 4;
/// Capability bit for MSH-26 per-link hop encryption (IDN-13/14).
///
/// The bit is signed inside `MeshHello`, so a relay cannot strip it. It only
/// enables the Control-frame handshake; the host still owns the cards,
/// handshake and session keys, and links without the bit stay cleartext.
pub const CAP_HOP_V1: u32 = 1 << 5;
/// Feature bits this build advertises by default (ADR-0001).
pub const CAPS: u32 = CAP_SYNC_V1 | CAP_SYNC_V2 | CAP_SPRAY_V1 | CAP_RECEIPT_V1 | CAP_PRESENCE_V1;

/// Every capability bit this build understands, including host-opted-in
/// hop encryption (MSH-26). [`MeshHello::sign_with_caps`] masks with this,
/// not with [`CAPS`], so a host that owns a `HopSessions` table can advertise
/// the extra bit without forging an unknown capability.
pub const SUPPORTED_CAPS: u32 = CAPS | CAP_HOP_V1;

/// Encoded length of a v1 hello: fixed, so a wrong length is rejected
/// before anything is read (ADR-0004).
pub const HELLO_LEN: usize = 161;

/// Bytes covered by the signature: everything before it.
const BODY_LEN: usize = 97;

/// A signed link introduction. Fields are public so a test can forge
/// hostile hellos; honest senders build one with [`MeshHello::sign`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshHello {
    /// Claimed identity; verification derives the real one from the keys.
    pub node_id: NodeId,
    /// Identity-card announcement hash, opaque to the mesh.
    pub card_hash: [u8; 8],
    /// Mesh format version the sender speaks.
    pub proto: u8,
    /// Feature bits the sender sets.
    pub caps: u32,
    /// Store summary digest, opaque to the mesh.
    pub store_digest: [u8; 4],
    /// Ed25519 signing key the signature is checked against.
    pub signing_pk: [u8; 32],
    /// X25519 agreement key; with `signing_pk` it derives `node_id`.
    pub agreement_pk: [u8; 32],
    /// Signature over `body()` under [`HELLO_DOMAIN`].
    pub signature: [u8; 64],
}

/// Why an introduction was rejected. Every variant has a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    /// Fewer bytes than the fixed layout needs; `need` is the first
    /// missing field's end.
    Truncated {
        /// Bytes the layout requires.
        need: usize,
        /// Bytes actually present.
        have: usize,
    },
    /// More bytes than the v1 layout defines: never guessed at.
    TrailingBytes {
        /// Bytes beyond [`HELLO_LEN`].
        extra: usize,
    },
    /// The signature did not verify: tampered field, foreign domain or
    /// a weak key, as aoIdents reports it.
    Verify(IdentError),
    /// A valid signature whose keys derive a different `node_id` than
    /// the hello claims.
    NodeIdMismatch {
        /// The claimed identity.
        claimed: NodeId,
        /// What the two keys actually derive.
        derived: NodeId,
    },
    /// No common mesh version at or above [`MIN_PROTO`].
    IncompatibleProto {
        /// The local version.
        local: u8,
        /// The version the hello claims.
        remote: u8,
    },
}
impl core::fmt::Display for HelloError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "mesh hello truncated: need {need} bytes, have {have}")
            }
            Self::TrailingBytes { extra } => {
                write!(f, "mesh hello has {extra} bytes beyond v1")
            }
            Self::Verify(e) => write!(f, "mesh hello signature rejected: {e}"),
            Self::NodeIdMismatch { claimed, derived } => write!(
                f,
                "mesh hello claims {claimed} but its keys derive {derived}"
            ),
            Self::IncompatibleProto { local, remote } => {
                write!(
                    f,
                    "mesh hello proto {remote} has no common version with {local}"
                )
            }
        }
    }
}
impl std::error::Error for HelloError {}

impl MeshHello {
    /// Builds and signs this build's hello: local `proto` and `caps`
    /// come from the crate constants so what a host advertises always
    /// matches what the engine negotiates with.
    pub fn sign(
        identity: &Identity,
        card_hash: [u8; 8],
        store_digest: [u8; 4],
    ) -> Result<Self, IdentError> {
        let public = identity.public();
        let mut hello = Self {
            node_id: identity.node_id(),
            card_hash,
            proto: PROTO,
            caps: CAPS,
            store_digest,
            signing_pk: *public.signing_pk(),
            agreement_pk: *public.agreement_pk(),
            signature: [0; 64],
        };
        let body = hello.body();
        hello.signature = *identity.sign(HELLO_DOMAIN, &body)?.as_bytes();
        Ok(hello)
    }

    /// Builds and signs a hello that opts into MSH-26 hop encryption.
    ///
    /// The host must also set [`crate::MeshConfig::hop_enabled`] so the
    /// engine negotiates the same bit. Cards, handshakes and keys stay with
    /// the host; this only publishes the signed capability and card pin.
    pub fn sign_with_hop(
        identity: &Identity,
        card_hash: [u8; 8],
        store_digest: [u8; 4],
    ) -> Result<Self, IdentError> {
        Self::sign_with_caps(identity, card_hash, store_digest, SUPPORTED_CAPS)
    }

    /// Builds and signs a hello with an explicit capability set.
    ///
    /// Hosts normally use [`Self::sign`]. This seam lets simulators and
    /// compatibility tests advertise a subset of this build's capabilities
    /// to exercise fallback without changing the signed layout.
    pub fn sign_with_caps(
        identity: &Identity,
        card_hash: [u8; 8],
        store_digest: [u8; 4],
        caps: u32,
    ) -> Result<Self, IdentError> {
        let public = identity.public();
        let mut hello = Self {
            node_id: identity.node_id(),
            card_hash,
            proto: PROTO,
            caps: caps & SUPPORTED_CAPS,
            store_digest,
            signing_pk: *public.signing_pk(),
            agreement_pk: *public.agreement_pk(),
            signature: [0; 64],
        };
        let body = hello.body();
        hello.signature = *identity.sign(HELLO_DOMAIN, &body)?.as_bytes();
        Ok(hello)
    }

    /// The exact v1 bytes: [`HELLO_LEN`] of them, ready for
    /// `AppHello::new(hello.encode().to_vec())`.
    pub fn encode(&self) -> [u8; HELLO_LEN] {
        let mut out = [0u8; HELLO_LEN];
        out[0..16].copy_from_slice(self.node_id.as_bytes());
        out[16..24].copy_from_slice(&self.card_hash);
        out[24] = self.proto;
        out[25..29].copy_from_slice(&self.caps.to_be_bytes());
        out[29..33].copy_from_slice(&self.store_digest);
        out[33..65].copy_from_slice(&self.signing_pk);
        out[65..97].copy_from_slice(&self.agreement_pk);
        out[97..161].copy_from_slice(&self.signature);
        out
    }

    /// Parses an introduction: exactly [`HELLO_LEN`] bytes or a typed
    /// error, read as fixed-offset fields so hostile lengths are decided
    /// before any byte is inspected.
    pub fn decode(bytes: &[u8]) -> Result<Self, HelloError> {
        if bytes.len() > HELLO_LEN {
            return Err(HelloError::TrailingBytes {
                extra: bytes.len() - HELLO_LEN,
            });
        }
        // Short input fails inside `array` as Truncated with the first
        // field that does not fit.
        Ok(Self {
            node_id: NodeId::from_bytes(array(bytes, 0)?),
            card_hash: array(bytes, 16)?,
            proto: array::<1>(bytes, 24)?[0],
            caps: u32::from_be_bytes(array(bytes, 25)?),
            store_digest: array(bytes, 29)?,
            signing_pk: array(bytes, 33)?,
            agreement_pk: array(bytes, 65)?,
            signature: array(bytes, 97)?,
        })
    }

    /// The bytes the signature covers: everything before it.
    pub fn body(&self) -> [u8; BODY_LEN] {
        let encoded = self.encode();
        let mut body = [0u8; BODY_LEN];
        body.copy_from_slice(&encoded[..BODY_LEN]);
        body
    }

    /// Verifies the signature under [`HELLO_DOMAIN`] and checks the
    /// claimed `node_id` against the derivation from its keys, yielding
    /// the verified [`NodeId`].
    pub fn verify(&self) -> Result<NodeId, HelloError> {
        let signature = Signature::from_bytes(self.signature);
        verify_signing_pk(&self.signing_pk, HELLO_DOMAIN, &self.body(), &signature)
            .map_err(HelloError::Verify)?;
        let derived = compute_node_id(&self.signing_pk, &self.agreement_pk);
        if derived != self.node_id {
            return Err(HelloError::NodeIdMismatch {
                claimed: self.node_id,
                derived,
            });
        }
        Ok(derived)
    }

    /// The link's mesh version and feature set: the lower `proto` of
    /// the two sides, never below [`MIN_PROTO`], and the `caps`
    /// intersection, so both ends agree without a round trip.
    pub fn negotiate(&self, local_proto: u8, local_caps: u32) -> Result<(u8, u32), HelloError> {
        let common = local_proto.min(self.proto);
        if common < MIN_PROTO {
            return Err(HelloError::IncompatibleProto {
                local: local_proto,
                remote: self.proto,
            });
        }
        Ok((common, local_caps & self.caps))
    }
}

/// The engine's one admission gate for a received `app_hello`: decode,
/// verify and negotiate, yielding the verified [`NodeId`] or the typed
/// reason the introduction was dropped.
pub fn verified_node_id(bytes: &[u8]) -> Result<NodeId, HelloError> {
    Ok(verified_hello(bytes)?.node_id)
}

/// The one admission gate for a received `app_hello`, returning the whole
/// verified introduction so the engine can read negotiated caps and the
/// advertised store digest without trusting the raw bytes twice.
pub fn verified_hello(bytes: &[u8]) -> Result<MeshHello, HelloError> {
    let hello = MeshHello::decode(bytes)?;
    hello.verify()?;
    hello.negotiate(PROTO, CAPS)?;
    Ok(hello)
}

/// One fixed-width field; the caller's length check makes failure
/// unreachable, but hostile input still gets a typed error rather than
/// a slice panic.
fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], HelloError> {
    bytes
        .get(at..at + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(HelloError::Truncated {
            need: at + N,
            have: bytes.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ao_idents::IdentError;

    /// Packet-domain context: a signature made for another registered
    /// use must not verify as a hello.
    const FOREIGN_DOMAIN: &str = "aoheyra/mesh/v1/packet";

    fn unsigned(identity: &Identity) -> MeshHello {
        MeshHello {
            node_id: identity.node_id(),
            card_hash: [0; 8],
            proto: PROTO,
            caps: CAPS,
            store_digest: [0; 4],
            signing_pk: *identity.public().signing_pk(),
            agreement_pk: *identity.public().agreement_pk(),
            signature: [0; 64],
        }
    }

    /// A structurally valid hello whose signature is made under `ctx`
    /// after `tweak` is applied to the fields.
    fn signed_under(
        identity: &Identity,
        ctx: &str,
        tweak: impl FnOnce(&mut MeshHello),
    ) -> MeshHello {
        let mut hello = unsigned(identity);
        tweak(&mut hello);
        let body = hello.body();
        hello.signature = *identity.sign(ctx, &body).unwrap().as_bytes();
        hello
    }

    /// Done when: a valid hello round-trips and verifies to the same
    /// verified NodeId.
    #[test]
    fn a_valid_hello_round_trips_and_verifies_to_the_same_node_id() {
        let identity = Identity::from_seed([42; 32]);
        let hello = MeshHello::sign(&identity, [7; 8], [9; 4]).unwrap();
        assert_eq!((hello.proto, hello.caps), (PROTO, CAPS));
        let decoded = MeshHello::decode(&hello.encode()).unwrap();
        assert_eq!(decoded, hello);
        let verified = decoded.verify().unwrap();
        assert_eq!(verified, identity.node_id());
        assert_eq!(verified_node_id(&hello.encode()).unwrap(), verified);
    }

    /// Hop is opt-in because only the host can drive its handshake. The
    /// default hello must stay cleartext for hosts that have not opted in;
    /// an opted-in engine must see the bit survive both signing and
    /// negotiation (MSH-26).
    #[test]
    fn hop_capability_is_signed_and_only_negotiated_when_both_sides_opt_in() {
        let identity = Identity::from_seed([43; 32]);
        let clear = MeshHello::sign(&identity, [7; 8], [9; 4]).unwrap();
        assert_eq!(clear.caps & CAP_HOP_V1, 0);
        assert_eq!(clear.negotiate(PROTO, CAPS).unwrap().1 & CAP_HOP_V1, 0);

        let hop = MeshHello::sign_with_hop(&identity, [7; 8], [9; 4]).unwrap();
        assert_eq!(hop.caps, SUPPORTED_CAPS);
        assert_eq!(
            hop.negotiate(PROTO, CAPS).unwrap().1 & CAP_HOP_V1,
            0,
            "a cleartext engine must not negotiate hop from a remote advertisement"
        );
        assert_ne!(
            hop.negotiate(PROTO, SUPPORTED_CAPS).unwrap().1 & CAP_HOP_V1,
            0
        );
    }

    /// Done when: a cut-off hello fails with a typed error, at every
    /// possible cut point.
    #[test]
    fn truncated_input_is_rejected_at_every_length() {
        let hello = MeshHello::sign(&Identity::from_seed([1; 32]), [0; 8], [0; 4]).unwrap();
        let encoded = hello.encode();
        for len in 0..HELLO_LEN {
            let err = MeshHello::decode(&encoded[..len]).unwrap_err().to_string();
            assert!(err.contains("truncated"), "len {len}: {err}");
        }
    }

    /// Done when: an oversize hello fails with a typed error, including
    /// the largest `AppHello` can ever deliver.
    #[test]
    fn oversize_input_is_rejected_at_every_length() {
        let hello = MeshHello::sign(&Identity::from_seed([2; 32]), [0; 8], [0; 4]).unwrap();
        for extra in [1usize, 2, 95, 96, 1024] {
            let mut longer = hello.encode().to_vec();
            longer.resize(HELLO_LEN + extra, 0);
            let err = MeshHello::decode(&longer).unwrap_err();
            assert_eq!(err, HelloError::TrailingBytes { extra });
        }
    }

    /// Done when: a tampered field fails with a typed error, wherever
    /// the tamper lands. Tampering inside `signing_pk` can produce a
    /// key that fails aoIdents' key validation before the signature is
    /// even checked, so the cause within `Verify` is either of the two
    /// hostile-input rejections.
    #[test]
    fn tampering_any_byte_breaks_verification() {
        let hello = MeshHello::sign(&Identity::from_seed([3; 32]), [0; 8], [0; 4]).unwrap();
        for idx in 0..HELLO_LEN {
            let mut tampered = hello.encode();
            tampered[idx] ^= 0x01;
            let decoded = MeshHello::decode(&tampered).unwrap();
            let err = decoded.verify().unwrap_err();
            let rejected = matches!(
                err,
                HelloError::Verify(IdentError::InvalidSignature | IdentError::InvalidPublicKey)
            );
            assert!(rejected, "byte {idx}: {err}");
        }
    }

    /// Done when: a signature under another domain fails with a typed
    /// error.
    #[test]
    fn a_signature_under_another_domain_is_rejected() {
        let identity = Identity::from_seed([4; 32]);
        let foreign = signed_under(&identity, FOREIGN_DOMAIN, |_| {});
        assert_eq!(
            foreign.verify(),
            Err(HelloError::Verify(IdentError::InvalidSignature))
        );
    }

    /// A valid signature over keys that do not derive the claimed id
    /// cannot borrow someone else's identity.
    #[test]
    fn a_node_id_the_keys_do_not_derive_is_rejected() {
        let signer = Identity::from_seed([5; 32]);
        let other = Identity::from_seed([6; 32]);
        let liar = signed_under(&signer, HELLO_DOMAIN, |hello| {
            hello.node_id = other.node_id();
        });
        assert_eq!(
            liar.verify(),
            Err(HelloError::NodeIdMismatch {
                claimed: other.node_id(),
                derived: signer.node_id(),
            })
        );
    }

    /// A hello below the version floor has no common language, so the
    /// introduction fails closed even though its signature is valid.
    #[test]
    fn proto_below_the_floor_is_rejected() {
        let identity = Identity::from_seed([7; 32]);
        let ancient = signed_under(&identity, HELLO_DOMAIN, |hello| hello.proto = MIN_PROTO - 1);
        assert_eq!(
            verified_node_id(&ancient.encode()),
            Err(HelloError::IncompatibleProto {
                local: PROTO,
                remote: 0
            })
        );
    }

    /// Fallback: a newer proto negotiates down to ours, and caps are
    /// the intersection, so both ends can compute it from one hello.
    #[test]
    fn a_newer_proto_falls_back_and_caps_are_intersected() {
        let identity = Identity::from_seed([8; 32]);
        let future = signed_under(&identity, HELLO_DOMAIN, |hello| {
            hello.proto = PROTO + 1;
            hello.caps = 0b1010;
        });
        assert_eq!(future.negotiate(PROTO, 0b1100).unwrap(), (PROTO, 0b1000));
        assert_eq!(
            verified_node_id(&future.encode()).unwrap(),
            identity.node_id()
        );
        // An older peer of ours: common = its proto, still above the floor.
        let older = signed_under(&identity, HELLO_DOMAIN, |hello| hello.proto = PROTO);
        assert_eq!(older.negotiate(PROTO + 1, u32::MAX).unwrap(), (PROTO, CAPS));
    }

    /// MSH-14: an honest hello advertises sync v1 and a peer without the
    /// bit negotiates it away, falling back to the MSH-13 beacon path.
    #[test]
    fn sync_v1_cap_is_advertised_and_can_be_negotiated_away() {
        let identity = Identity::from_seed([11; 32]);
        let hello = MeshHello::sign(&identity, [0; 8], [0; 4]).unwrap();
        assert_ne!(hello.caps & CAP_SYNC_V1, 0);
        assert_ne!(hello.negotiate(PROTO, CAPS).unwrap().1 & CAP_SYNC_V1, 0);
        assert_eq!(hello.negotiate(PROTO, 0).unwrap().1 & CAP_SYNC_V1, 0);
    }

    /// MSH-19: an honest hello advertises presence announcements. A peer
    /// without the bit negotiates it away and keeps the pre-MSH-19 Presence
    /// relay path.
    #[test]
    fn presence_cap_is_advertised_and_can_be_negotiated_away() {
        let identity = Identity::from_seed([13; 32]);
        let hello = MeshHello::sign(&identity, [0; 8], [0; 4]).unwrap();
        assert_ne!(hello.caps & CAP_PRESENCE_V1, 0);
        assert_ne!(hello.negotiate(PROTO, CAPS).unwrap().1 & CAP_PRESENCE_V1, 0);
        let old = MeshHello::sign_with_caps(&identity, [0; 8], [0; 4], CAP_SYNC_V1).unwrap();
        let caps = old.negotiate(PROTO, CAPS).unwrap().1;
        assert_eq!(caps & CAP_PRESENCE_V1, 0);
    }

    /// MSH-15: an honest hello also advertises sync v2. A v1-only peer
    /// negotiates it away and keeps the MSH-14 summary exchange.
    #[test]
    fn sync_v2_cap_is_advertised_and_negotiates_down_to_v1() {
        let identity = Identity::from_seed([12; 32]);
        let hello = MeshHello::sign(&identity, [0; 8], [0; 4]).unwrap();
        assert_ne!(hello.caps & CAP_SYNC_V2, 0);
        assert_ne!(hello.negotiate(PROTO, CAPS).unwrap().1 & CAP_SYNC_V2, 0);
        let v1_only = MeshHello::sign_with_caps(&identity, [0; 8], [0; 4], CAP_SYNC_V1).unwrap();
        let caps = v1_only.negotiate(PROTO, CAPS).unwrap().1;
        assert_ne!(caps & CAP_SYNC_V1, 0);
        assert_eq!(caps & CAP_SYNC_V2, 0);
    }

    /// Done when: the encoded hello carries exactly the v1 layout. The
    /// fit within aoNetwork's 256-byte limit is a compile-time assert
    /// in lib.rs and an `AppHello` round trip in tests/hello.rs.
    #[test]
    fn the_layout_is_pinned_to_the_v1_length() {
        let hello = MeshHello::sign(&Identity::from_seed([9; 32]), [0; 8], [0; 4]).unwrap();
        assert_eq!(hello.encode().len(), HELLO_LEN);
    }

    /// One message per rejection, and every message says which one.
    #[test]
    fn display_is_informative_for_every_variant() {
        let a = NodeId::from_bytes([1; 16]);
        let b = NodeId::from_bytes([2; 16]);
        let cases = [
            (
                HelloError::Truncated { need: 161, have: 3 },
                "need 161 bytes, have 3",
            ),
            (HelloError::TrailingBytes { extra: 4 }, "4 bytes beyond"),
            (
                HelloError::Verify(IdentError::InvalidSignature),
                "signature rejected",
            ),
            (
                HelloError::NodeIdMismatch {
                    claimed: a,
                    derived: b,
                },
                "keys derive",
            ),
            (
                HelloError::IncompatibleProto {
                    local: 1,
                    remote: 0,
                },
                "no common version",
            ),
        ];
        for (err, needle) in cases {
            let shown = err.to_string();
            assert!(shown.contains("mesh hello"), "{shown}");
            assert!(shown.contains(needle), "{shown}");
        }
    }
}
