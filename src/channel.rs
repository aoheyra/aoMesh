//! Public-channel rules (MSH-23).
//!
//! A public channel is **not** a new packet class or a new header field. It
//! is a fixed envelope inside the opaque payload of an ordinary signed
//! `Broadcast` packet:
//!
//! ```text
//! offset  size        field
//! 0       1           magic (`CHANNEL_MAGIC`)
//! 1       1           version (`CHANNEL_VERSION`)
//! 2       16          channel id
//! 18      ..          opaque application payload
//! ```
//!
//! The channel id is a domain-separated BLAKE3 hash of the channel name,
//! truncated to 16 bytes. The name is never sent on the wire: subscribers
//! derive the same id locally. The hash uses the same primitive and domain
//! convention as [`crate::sign`]'s content addresses; it is not a new
//! cryptographic primitive. Because a 128-bit digest can in principle
//! collide, a local subscription table binds each id to the name that
//! claimed it and refuses a second, different name for the same id with
//! [`ChannelError::IdCollision`].
//!
//! The mesh sees only opaque envelope bytes. It never reads message text or
//! any app schema. Signing and verification are unchanged: the origin signs
//! the packet's immutable prefix with [`crate::sign::sign_packet`], and the
//! payload (including the envelope) is bound to that signature through
//! `msg_id`. Receivers verify with the same registered domain before a
//! local `ChannelDeliver` is emitted.
//!
//! Relays do not track subscriptions. They forward channel packets on the
//! normal Broadcast path and pay the same MSH-10 origin/link budgets and
//! MSH-11 suppression they would for any Broadcast. On top of that, the
//! channel key is debited from the same token-bucket table under a domain-
//! separated synthetic origin, so a hot channel cannot exhaust the shared
//! Broadcast allowance. No parallel budget, timer or cache is introduced.

use ao_idents::NodeId;
use std::collections::BTreeMap;
use std::fmt;

use crate::packet::MAX_PAYLOAD;

/// Signature-domain-style BLAKE3 domain for channel ids (MSH-23).
///
/// Registered here alongside the mesh's other hash domains in
/// `docs/protocol.md`; the one-byte length prefix keeps the name from being
/// confused with a concatenation of other fields.
const CHANNEL_ID_DOMAIN: &str = "aoheyra/mesh/v1/channel-id";
/// Separate domain for the synthetic budget key. A channel id is never
/// treated as a node identity; hashing it again under its own domain keeps
/// the two 16-byte keys from being interchangeable.
const CHANNEL_BUDGET_DOMAIN: &str = "aoheyra/mesh/v1/channel-budget";
/// Tag for the single channel-id hash form; reserved so a v2 envelope can
/// add a form without reusing the v1 digest space.
const CHANNEL_ID_TAG: u8 = 0x01;

/// Size of a channel id on and off the wire.
pub const CHANNEL_ID_LEN: usize = 16;
/// First byte of a v1 channel envelope. Ordinary Broadcast payloads that
/// do not start with this byte take the unchanged MSH-11 path.
pub const CHANNEL_MAGIC: u8 = 0xC4;
/// Envelope version carried in byte 1.
pub const CHANNEL_VERSION: u8 = 1;
/// Fixed bytes before the opaque payload.
pub const CHANNEL_HEADER_LEN: usize = 2 + CHANNEL_ID_LEN;
/// Hard cap on a channel name. The config bound cannot exceed it.
pub const MAX_CHANNEL_NAME_LEN: usize = 64;
/// Hard cap on local subscriptions; keeps the name registry bounded even
/// if a host asks for a very large config.
pub const MAX_CHANNEL_SUBSCRIPTIONS: usize = 256;

/// A deterministic channel identifier: 16 bytes derived from a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId([u8; CHANNEL_ID_LEN]);

impl ChannelId {
    /// Wraps raw identifier bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHANNEL_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHANNEL_ID_LEN] {
        &self.0
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Which replayed allowance refused a channel submission (MSH-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelBudgetScope {
    /// The per-channel Broadcast bucket is empty.
    Channel,
    /// The sending origin's Broadcast bucket is empty.
    Origin,
}

/// A typed channel failure. No packet-driven path panics or guesses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// A channel name was empty.
    EmptyName,
    /// A channel name exceeded the configured bound.
    NameTooLong {
        /// Name length supplied by the host.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// An envelope ended before the fixed header.
    EnvelopeTooShort {
        /// Required header bytes.
        need: usize,
        /// Bytes present.
        have: usize,
    },
    /// The first byte is not the v1 channel magic.
    WrongMagic(u8),
    /// The envelope version is not [`CHANNEL_VERSION`].
    UnsupportedVersion(u8),
    /// Envelope plus opaque payload would exceed [`MAX_PAYLOAD`].
    PayloadTooLarge {
        /// Requested envelope length.
        len: usize,
        /// Cap, [`MAX_PAYLOAD`].
        max: usize,
    },
    /// No more local subscriptions fit the configured bound.
    SubscriptionsFull {
        /// Configured maximum.
        limit: usize,
    },
    /// Two different names claimed one channel id.
    ///
    /// BLAKE3-128 makes this infeasible by chance; the registry still fails
    /// closed rather than silently merging two channels if it happens.
    IdCollision {
        /// The contested identifier.
        id: ChannelId,
    },
    /// A local submission exceeded a channel or origin budget.
    BudgetDenied {
        /// Which allowance was empty.
        scope: ChannelBudgetScope,
    },
    /// A config value was outside its hard, documented bound.
    InvalidConfig,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "channel name is empty"),
            Self::NameTooLong { len, max } => {
                write!(f, "channel name is {len} bytes, cap is {max}")
            }
            Self::EnvelopeTooShort { need, have } => {
                write!(f, "channel envelope needs {need} bytes, has {have}")
            }
            Self::WrongMagic(byte) => write!(f, "unknown channel magic {byte:#04x}"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported channel version {version}"),
            Self::PayloadTooLarge { len, max } => {
                write!(f, "channel payload is {len} bytes, cap is {max}")
            }
            Self::SubscriptionsFull { limit } => {
                write!(f, "channel subscriptions are full at {limit}")
            }
            Self::IdCollision { id } => write!(f, "channel id {id} has two names"),
            Self::BudgetDenied { scope } => match scope {
                ChannelBudgetScope::Channel => write!(f, "per-channel Broadcast budget exhausted"),
                ChannelBudgetScope::Origin => write!(f, "per-origin Broadcast budget exhausted"),
            },
            Self::InvalidConfig => write!(f, "channel config exceeds its hard bound"),
        }
    }
}

impl std::error::Error for ChannelError {}

/// Derives a channel id from its name.
///
/// The digest covers the registered domain, a one-byte name length and the
/// name itself, then truncates to [`CHANNEL_ID_LEN`]. Names are bounded
/// before hashing so a hostile host input cannot drive unbounded CPU.
pub fn derive_channel_id(name: &[u8]) -> Result<ChannelId, ChannelError> {
    if name.is_empty() {
        return Err(ChannelError::EmptyName);
    }
    if name.len() > MAX_CHANNEL_NAME_LEN {
        return Err(ChannelError::NameTooLong {
            len: name.len(),
            max: MAX_CHANNEL_NAME_LEN,
        });
    }
    Ok(derive_channel_id_unchecked(name))
}

fn derive_channel_id_unchecked(name: &[u8]) -> ChannelId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHANNEL_ID_DOMAIN.as_bytes());
    hasher.update(&[name.len() as u8]);
    hasher.update(&[CHANNEL_ID_TAG]);
    hasher.update(name);
    let digest = hasher.finalize();
    let mut id = [0u8; CHANNEL_ID_LEN];
    id.copy_from_slice(&digest.as_bytes()[..CHANNEL_ID_LEN]);
    ChannelId::from_bytes(id)
}

/// The synthetic budget key for one channel.
///
/// It is a key into the existing MSH-10 token-bucket table, not an identity:
/// the extra hash domain prevents any confusion with a real `NodeId`.
#[must_use]
pub fn channel_budget_origin(id: ChannelId) -> NodeId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHANNEL_BUDGET_DOMAIN.as_bytes());
    hasher.update(&[CHANNEL_ID_LEN as u8]);
    hasher.update(id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    NodeId::from_bytes(bytes)
}

/// Bounds for a node's local channel registry.
///
/// Both values are validated against hard caps by [`ChannelConfig::new`], so
/// engine state cannot be made unbounded by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelConfig {
    max_subscriptions: usize,
    max_name_len: usize,
}

impl ChannelConfig {
    /// Validates and builds a config.
    ///
    /// Returns [`ChannelError::InvalidConfig`] when a bound is zero or above
    /// its hard cap. No silent clamping: a host must notice a bad request.
    pub fn new(max_subscriptions: usize, max_name_len: usize) -> Result<Self, ChannelError> {
        if max_subscriptions == 0
            || max_subscriptions > MAX_CHANNEL_SUBSCRIPTIONS
            || max_name_len == 0
            || max_name_len > MAX_CHANNEL_NAME_LEN
        {
            return Err(ChannelError::InvalidConfig);
        }
        Ok(Self {
            max_subscriptions,
            max_name_len,
        })
    }

    /// Maximum number of locally declared subscriptions.
    #[must_use]
    pub const fn max_subscriptions(&self) -> usize {
        self.max_subscriptions
    }

    /// Maximum bytes in a channel name.
    #[must_use]
    pub const fn max_name_len(&self) -> usize {
        self.max_name_len
    }
}

impl Default for ChannelConfig {
    /// 32 channels with 64-byte names: at most 2 KiB of name state plus id
    /// keys, well inside a phone's memory budget.
    fn default() -> Self {
        Self {
            max_subscriptions: 32,
            max_name_len: MAX_CHANNEL_NAME_LEN,
        }
    }
}

/// A parsed channel envelope borrowing its opaque payload from the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelEnvelope<'a> {
    /// Deterministic id of the channel.
    pub channel_id: ChannelId,
    /// Opaque application bytes. The mesh never interprets them.
    pub payload: &'a [u8],
}

impl<'a> ChannelEnvelope<'a> {
    /// Wraps opaque bytes in a v1 envelope, enforcing the packet cap.
    pub fn new(channel_id: ChannelId, payload: &'a [u8]) -> Result<Self, ChannelError> {
        let len =
            payload
                .len()
                .checked_add(CHANNEL_HEADER_LEN)
                .ok_or(ChannelError::PayloadTooLarge {
                    len: usize::MAX,
                    max: MAX_PAYLOAD,
                })?;
        if len > MAX_PAYLOAD {
            return Err(ChannelError::PayloadTooLarge {
                len,
                max: MAX_PAYLOAD,
            });
        }
        Ok(Self {
            channel_id,
            payload,
        })
    }

    /// Parses the fixed header without allocating or reading beyond it.
    ///
    /// [`crate::Packet::decode`] has already capped the packet payload, so
    /// the borrowed opaque bytes are bounded before this call.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ChannelError> {
        if bytes.len() < CHANNEL_HEADER_LEN {
            return Err(ChannelError::EnvelopeTooShort {
                need: CHANNEL_HEADER_LEN,
                have: bytes.len(),
            });
        }
        if bytes[0] != CHANNEL_MAGIC {
            return Err(ChannelError::WrongMagic(bytes[0]));
        }
        if bytes[1] != CHANNEL_VERSION {
            return Err(ChannelError::UnsupportedVersion(bytes[1]));
        }
        let mut id = [0u8; CHANNEL_ID_LEN];
        id.copy_from_slice(&bytes[2..CHANNEL_HEADER_LEN]);
        Ok(Self {
            channel_id: ChannelId::from_bytes(id),
            payload: &bytes[CHANNEL_HEADER_LEN..],
        })
    }

    /// Encodes the envelope for use as a Broadcast packet payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHANNEL_HEADER_LEN + self.payload.len());
        out.push(CHANNEL_MAGIC);
        out.push(CHANNEL_VERSION);
        out.extend_from_slice(self.channel_id.as_bytes());
        out.extend_from_slice(self.payload);
        out
    }
}

/// Bounded, local-only subscription registry.
///
/// A relay that never receives a [`crate::MeshInput::ChannelSubscribe`]
/// keeps this empty: forwarding needs no subscription state.
#[derive(Debug)]
pub struct ChannelRules {
    config: ChannelConfig,
    names: BTreeMap<ChannelId, Vec<u8>>,
}

impl ChannelRules {
    pub(crate) fn new(config: ChannelConfig) -> Self {
        Self {
            config,
            names: BTreeMap::new(),
        }
    }

    /// Number of local subscriptions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether no channel is subscribed locally.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Whether `id` is subscribed on this node.
    #[must_use]
    pub fn contains(&self, id: ChannelId) -> bool {
        self.names.contains_key(&id)
    }

    /// Records a local subscription by name and returns its derived id.
    ///
    /// Re-subscribing the same name is idempotent; a different name that
    /// derives to an existing id is refused rather than merging channels.
    pub fn subscribe(&mut self, name: &[u8]) -> Result<ChannelId, ChannelError> {
        self.check_name(name)?;
        let id = derive_channel_id_unchecked(name);
        self.bind(id, name)?;
        Ok(id)
    }

    /// Removes a local subscription by name. Unknown names are a no-op.
    pub fn unsubscribe(&mut self, name: &[u8]) -> Result<(), ChannelError> {
        self.check_name(name)?;
        let id = derive_channel_id_unchecked(name);
        match self.names.get(&id) {
            Some(bound) if bound.as_slice() != name => {
                return Err(ChannelError::IdCollision { id });
            }
            Some(_) => {
                self.names.remove(&id);
            }
            None => {}
        }
        Ok(())
    }

    fn check_name(&self, name: &[u8]) -> Result<(), ChannelError> {
        if name.is_empty() {
            return Err(ChannelError::EmptyName);
        }
        if name.len() > self.config.max_name_len {
            return Err(ChannelError::NameTooLong {
                len: name.len(),
                max: self.config.max_name_len,
            });
        }
        Ok(())
    }

    fn bind(&mut self, id: ChannelId, name: &[u8]) -> Result<(), ChannelError> {
        if let Some(bound) = self.names.get(&id) {
            if bound.as_slice() != name {
                return Err(ChannelError::IdCollision { id });
            }
            return Ok(());
        }
        if self.names.len() >= self.config.max_subscriptions {
            return Err(ChannelError::SubscriptionsFull {
                limit: self.config.max_subscriptions,
            });
        }
        self.names.insert(id, name.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Header, Packet, PacketClass, sign_packet, verify_origin};
    use ao_idents::Identity;

    fn identity() -> Identity {
        Identity::from_seed([23; 32])
    }

    #[test]
    fn channel_id_is_domain_separated_and_bounded() {
        let a = derive_channel_id(b"town-square").expect("name is valid");
        assert_eq!(a, derive_channel_id(b"town-square").expect("name is valid"));
        assert_ne!(
            a,
            derive_channel_id(b"town-square ").expect("name is valid")
        );
        assert_ne!(channel_budget_origin(a), NodeId::from_bytes(*a.as_bytes()));
        assert_eq!(derive_channel_id(b""), Err(ChannelError::EmptyName));
        assert_eq!(
            derive_channel_id(&[b'x'; MAX_CHANNEL_NAME_LEN + 1]),
            Err(ChannelError::NameTooLong {
                len: MAX_CHANNEL_NAME_LEN + 1,
                max: MAX_CHANNEL_NAME_LEN,
            })
        );
        assert_eq!(a.to_string().len(), 2 * CHANNEL_ID_LEN);
    }

    #[test]
    fn distinct_names_have_distinct_ids_and_collisions_fail_closed() {
        let names: [&[u8]; 32] = [
            b"alpha",
            b"bravo",
            b"charlie",
            b"delta",
            b"echo",
            b"foxtrot",
            b"golf",
            b"hotel",
            b"india",
            b"juliet",
            b"kilo",
            b"lima",
            b"mike",
            b"november",
            b"oscar",
            b"papa",
            b"quebec",
            b"romeo",
            b"sierra",
            b"tango",
            b"uniform",
            b"victor",
            b"whiskey",
            b"x-ray",
            b"yankee",
            b"zulu",
            b"a",
            b"b",
            b"c",
            b"1",
            b"2",
            b"3",
        ];
        let mut ids = std::collections::BTreeSet::new();
        for name in names {
            assert!(ids.insert(derive_channel_id(name).expect("valid name")));
        }
        let mut rules = ChannelRules::new(ChannelConfig::default());
        let first = rules.subscribe(b"alpha").expect("first name");
        assert_eq!(rules.subscribe(b"alpha"), Ok(first));
        // A forced binding models the collision that BLAKE3-128 makes
        // infeasible; the registry must not silently merge two names.
        assert_eq!(
            rules.bind(first, b"bravo"),
            Err(ChannelError::IdCollision { id: first })
        );
        assert_eq!(rules.len(), 1);
        assert!(rules.contains(first));
    }

    #[test]
    fn subscription_state_is_bounded() {
        let config = ChannelConfig::new(2, 4).expect("valid config");
        let mut rules = ChannelRules::new(config);
        assert_eq!(
            rules.subscribe(b"abcd"),
            Ok(derive_channel_id(b"abcd").expect("name"))
        );
        assert_eq!(
            rules.subscribe(b"efgh"),
            Ok(derive_channel_id(b"efgh").expect("name"))
        );
        assert_eq!(
            rules.subscribe(b"ijkl"),
            Err(ChannelError::SubscriptionsFull { limit: 2 })
        );
        assert_eq!(
            rules.subscribe(b"abcde"),
            Err(ChannelError::NameTooLong { len: 5, max: 4 })
        );
        rules.unsubscribe(b"abcd").expect("remove");
        assert_eq!(rules.len(), 1);
        assert!(rules.subscribe(b"ijkl").is_ok());
        assert_eq!(ChannelConfig::new(0, 4), Err(ChannelError::InvalidConfig));
        assert_eq!(
            ChannelConfig::new(1, MAX_CHANNEL_NAME_LEN + 1),
            Err(ChannelError::InvalidConfig)
        );
    }

    #[test]
    fn envelope_round_trip_and_header_first_reject() {
        let id = derive_channel_id(b"town-square").expect("name");
        let envelope = ChannelEnvelope::new(id, b"opaque").expect("small payload");
        let bytes = envelope.encode();
        assert_eq!(bytes.len(), CHANNEL_HEADER_LEN + 6);
        assert_eq!(ChannelEnvelope::decode(&bytes), Ok(envelope));
        assert_eq!(
            ChannelEnvelope::decode(&bytes[..CHANNEL_HEADER_LEN - 1]),
            Err(ChannelError::EnvelopeTooShort {
                need: CHANNEL_HEADER_LEN,
                have: CHANNEL_HEADER_LEN - 1,
            })
        );
        let mut corrupt = bytes.clone();
        corrupt[0] = 0;
        assert_eq!(
            ChannelEnvelope::decode(&corrupt),
            Err(ChannelError::WrongMagic(0))
        );
        corrupt = bytes.clone();
        corrupt[1] = CHANNEL_VERSION + 1;
        assert_eq!(
            ChannelEnvelope::decode(&corrupt),
            Err(ChannelError::UnsupportedVersion(CHANNEL_VERSION + 1))
        );
        assert_eq!(
            ChannelEnvelope::new(id, &[0; MAX_PAYLOAD]),
            Err(ChannelError::PayloadTooLarge {
                len: MAX_PAYLOAD + CHANNEL_HEADER_LEN,
                max: MAX_PAYLOAD,
            })
        );
    }

    #[test]
    fn channel_payload_uses_the_unchanged_signature_scheme() {
        let sender = identity();
        let id = derive_channel_id(b"town-square").expect("name");
        let envelope = ChannelEnvelope::new(id, b"opaque bytes").expect("small payload");
        let payload = envelope.encode();
        let mut header = Header {
            class: PacketClass::Broadcast,
            dst: None,
            msg_id: [0; 16].into(),
            origin: [0; 16],
            created_ms: 1_700_000_000_000,
            lifetime_s: 600,
            payload_len: payload.len() as u64,
            ttl: 6,
            hops: 0,
        };
        let signature = sign_packet(&sender, &mut header, &payload).expect("fixed key signs");
        let wire = Packet::new(header, signature, &payload)
            .expect("lengths agree")
            .encode();
        let mut decoded = Packet::decode(&wire).expect("wire round trip");
        verify_origin(
            sender.public(),
            &decoded.header,
            decoded.payload,
            &decoded.signature,
        )
        .expect("honest channel packet verifies");
        assert_eq!(
            ChannelEnvelope::decode(decoded.payload).expect("envelope"),
            envelope
        );
        decoded.header.ttl -= 1;
        decoded.header.hops += 1;
        verify_origin(
            sender.public(),
            &decoded.header,
            decoded.payload,
            &decoded.signature,
        )
        .expect("hop fields stay outside the signed prefix");
        let tampered = {
            let mut p = decoded;
            p.payload = b"tampered bytes";
            p
        };
        assert!(
            verify_origin(
                sender.public(),
                &tampered.header,
                tampered.payload,
                &tampered.signature
            )
            .is_err()
        );
    }

    #[test]
    fn display_is_informative_for_every_error() {
        let id = derive_channel_id(b"x").expect("name");
        let errors = [
            ChannelError::EmptyName,
            ChannelError::NameTooLong { len: 2, max: 1 },
            ChannelError::EnvelopeTooShort { need: 18, have: 2 },
            ChannelError::WrongMagic(0),
            ChannelError::UnsupportedVersion(9),
            ChannelError::PayloadTooLarge { len: 9, max: 8 },
            ChannelError::SubscriptionsFull { limit: 1 },
            ChannelError::IdCollision { id },
            ChannelError::BudgetDenied {
                scope: ChannelBudgetScope::Channel,
            },
            ChannelError::BudgetDenied {
                scope: ChannelBudgetScope::Origin,
            },
            ChannelError::InvalidConfig,
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
}
