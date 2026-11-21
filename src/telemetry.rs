//! Bounded latest-wins policy for the Telemetry class (MSH-22).
//!
//! Telemetry is ambient state, not a message: it is signed like any other
//! packet, relayed inside a three-hop radius, never stored or synced, and
//! superseded by the next update from the same origin and kind. This module
//! owns the *policy* only: the small opaque kind tag, the monotonic sequence,
//! the coalesce key aoNetwork uses for NET-21 send-queue coalescing, the
//! freshness deadline and the per-origin throttle.
//!
//! The payload stays opaque. The frame prefix below carries no application
//! schema; the mesh never reads a location, only `kind` and `seq`. No clock,
//! RNG, I/O or radio queue lives here. `now` is the caller's monotonic
//! millisecond clock, and remote `created_ms` is deliberately ignored, so a
//! skewed peer clock cannot extend or shorten a local deadline.

use crate::packet::MAX_PAYLOAD;
use std::collections::BTreeMap;

/// Domain separating coalesce keys from every other hash in the mesh.
const COALESCE_DOMAIN: &[u8] = b"aoheyra/mesh/v1/telemetry/coalesce";
/// Version of the small Telemetry payload frame; future versions need a new
/// class or an explicit capability, never silent reinterpretation.
pub const TELEMETRY_VERSION: u8 = 1;
/// Fixed bytes prepended to an opaque Telemetry payload: version, kind, seq.
pub const TELEMETRY_PREFIX_LEN: usize = 1 + 1 + 8;
/// Default freshness of one update, in milliseconds (ADR-0001's ~30 s).
pub const DEFAULT_EXPIRY_MS: u64 = 30_000;
/// Default relay hop limit (ADR-0001 and `SuppressionConfig::telemetry_ttl`).
pub const DEFAULT_HOP_LIMIT: u8 = 3;
/// Default minimum interval between accepted updates from one origin.
pub const DEFAULT_RATE_LIMIT_MS: u64 = 10_000;
/// Default bound on live per-(origin, kind) entries.
pub const DEFAULT_MAX_ENTRIES: usize = 512;

/// An opaque one-byte kind tag.
///
/// aoMesh never interprets it: kind 7 is no more "location" than kind 9. The
/// application owns the meaning and uses distinct tags for independent
/// latest-wins streams, which is what makes the coalesce key stable across
/// updates of one stream and different across streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TelemetryKind(u8);

impl TelemetryKind {
    /// Wraps an opaque tag byte.
    #[must_use]
    pub const fn new(byte: u8) -> Self {
        Self(byte)
    }
    /// The tag byte, unchanged.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for TelemetryKind {
    fn from(byte: u8) -> Self {
        Self(byte)
    }
}

/// Opaque 16-byte key handed to aoNetwork's NET-21 send queue.
///
/// The queue only compares bytes; deriving it here keeps the origin and kind
/// in one place and prevents the host from inventing a second hashing rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoalesceKey([u8; 16]);

impl CoalesceKey {
    /// Raw key bytes, in the form aoNetwork expects.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Derives the latest-wins key for `(origin, kind)`.
///
/// BLAKE3 is already a dependency for `msg_id`; a separate domain keeps a
/// coalesce key from ever colliding with a content address. The sequence is
/// *not* hashed: the key must stay constant so a newer update replaces the
/// older one still waiting in a send queue.
#[must_use]
pub fn coalesce_key(origin: &[u8; 16], kind: TelemetryKind) -> CoalesceKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COALESCE_DOMAIN);
    hasher.update(origin);
    hasher.update(&[kind.as_u8()]);
    let digest = hasher.finalize();
    let mut out = [0; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    CoalesceKey(out)
}

/// A typed Telemetry policy failure or drop reason.
///
/// Submit uses every variant as a `MeshError`; relays use the same type to
/// distinguish an attributable malformed frame from an ordinary policy drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryError {
    /// The frame ends before the fixed prefix. `need` counts the prefix.
    TooShort {
        /// Minimum bytes required.
        need: usize,
        /// Bytes present.
        have: usize,
    },
    /// The frame's version byte is not [`TELEMETRY_VERSION`].
    UnsupportedVersion(u8),
    /// The framed payload would exceed the packet payload cap.
    PayloadTooLarge {
        /// Framed length requested by the host.
        len: usize,
        /// Cap, [`MAX_PAYLOAD`].
        max: usize,
    },
    /// The sender's effective lifetime is already zero.
    Expired,
    /// A sequence equal to or older than the newest accepted one arrived.
    Stale {
        /// Newest sequence already accepted for this key.
        last_seq: u64,
        /// Sequence that arrived.
        seen: u64,
    },
    /// This origin accepted an update less than the configured interval ago.
    RateLimited {
        /// Milliseconds until the next update could be accepted.
        retry_ms: u64,
    },
    /// No relay hop remains, or the class hop limit is one or zero.
    HopLimit,
    /// The configured state bound is zero; no policy entry can be kept.
    NoCapacity,
}

impl core::fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { need, have } => {
                write!(f, "telemetry frame needs {need} bytes, has {have}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported telemetry frame version {version}")
            }
            Self::PayloadTooLarge { len, max } => {
                write!(f, "framed telemetry payload {len} exceeds cap {max}")
            }
            Self::Expired => write!(f, "telemetry update has no lifetime left"),
            Self::Stale { last_seq, seen } => {
                write!(f, "telemetry sequence {seen} is not newer than {last_seq}")
            }
            Self::RateLimited { retry_ms } => {
                write!(f, "telemetry origin throttled for {retry_ms} ms")
            }
            Self::HopLimit => write!(f, "telemetry has no relay hop left"),
            Self::NoCapacity => write!(f, "telemetry state bound is zero"),
        }
    }
}

impl std::error::Error for TelemetryError {}

/// A borrowed view of the fixed Telemetry frame prefix.
///
/// Decoding reads only the prefix and borrows the rest, so a hostile packet
/// costs no allocation before the header and content address are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryFrame<'a> {
    /// Opaque kind tag from byte 1.
    pub kind: TelemetryKind,
    /// Sender-monotonic sequence from bytes 2..10.
    pub seq: u64,
    /// Opaque application bytes; the mesh never reads them.
    pub payload: &'a [u8],
}

impl<'a> TelemetryFrame<'a> {
    /// Wraps a framed payload into the wire prefix.
    ///
    /// Returns a typed error before allocating when the framed length would
    /// exceed [`MAX_PAYLOAD`].
    pub fn encode(
        kind: TelemetryKind,
        seq: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, TelemetryError> {
        let len = TELEMETRY_PREFIX_LEN.checked_add(payload.len()).ok_or(
            TelemetryError::PayloadTooLarge {
                len: usize::MAX,
                max: MAX_PAYLOAD,
            },
        )?;
        if len > MAX_PAYLOAD {
            return Err(TelemetryError::PayloadTooLarge {
                len,
                max: MAX_PAYLOAD,
            });
        }
        let mut out = Vec::with_capacity(len);
        out.push(TELEMETRY_VERSION);
        out.push(kind.as_u8());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Parses the prefix without copying the opaque payload.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, TelemetryError> {
        if bytes.len() < TELEMETRY_PREFIX_LEN {
            return Err(TelemetryError::TooShort {
                need: TELEMETRY_PREFIX_LEN,
                have: bytes.len(),
            });
        }
        if bytes[0] != TELEMETRY_VERSION {
            return Err(TelemetryError::UnsupportedVersion(bytes[0]));
        }
        let kind = TelemetryKind::new(bytes[1]);
        let mut seq_bytes = [0; 8];
        seq_bytes.copy_from_slice(&bytes[2..TELEMETRY_PREFIX_LEN]);
        Ok(Self {
            kind,
            seq: u64::from_be_bytes(seq_bytes),
            payload: &bytes[TELEMETRY_PREFIX_LEN..],
        })
    }
}

/// What the engine advertises with every accepted Telemetry send.
///
/// The advisory carries only bounded policy values: a fixed-size key, the
/// opaque kind and sequence, a freshness window already shortened by the
/// sender's own lifetime, and the class hop limit. aoNetwork uses the key and
/// deadline in NET-21; it never sees the payload schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryAdvisory {
    /// Latest-wins key for the send queue.
    pub coalesce_key: CoalesceKey,
    /// Opaque kind this update belongs to.
    pub kind: TelemetryKind,
    /// Monotonic sequence that was accepted.
    pub seq: u64,
    /// Milliseconds of freshness left from the local `now`.
    pub expires_in_ms: u64,
    /// Hop limit applied to this class.
    pub hop_limit: u8,
}

/// Configurable Telemetry bounds and timers.
///
/// Defaults are ADR-0001's ~30 s freshness and three-hop radius plus the
/// one-per-10 s per-origin throttle from MSH-22. They are config-driven and
/// bounded so a hostile peer cannot grow engine state or mint freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryConfig {
    /// Maximum freshness of one update, in milliseconds.
    pub expiry_ms: u64,
    /// Minimum interval between accepted updates from one origin.
    pub rate_limit_ms: u64,
    /// Relay hop limit; also clamped on typed submission.
    pub hop_limit: u8,
    /// Bound on live `(origin, kind)` freshness entries.
    pub max_entries: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            expiry_ms: DEFAULT_EXPIRY_MS,
            rate_limit_ms: DEFAULT_RATE_LIMIT_MS,
            hop_limit: DEFAULT_HOP_LIMIT,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

impl TelemetryConfig {
    /// Effective freshness window for a sender-declared lifetime.
    ///
    /// A local ceiling may shorten the sender's claim but never extend it.
    /// Wide arithmetic keeps a hostile `lifetime_s` from overflowing.
    #[must_use]
    pub fn effective_expiry_ms(&self, sender_lifetime_s: u64) -> u64 {
        let sender =
            u64::try_from(u128::from(sender_lifetime_s).saturating_mul(1000)).unwrap_or(u64::MAX);
        sender.min(self.expiry_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TelemetryKey {
    kind: TelemetryKind,
    origin: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Freshness {
    seq: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rate {
    accepted_at_ms: u64,
}

/// Deterministic, bounded latest-wins state for all Telemetry origins.
///
/// Freshness entries are bounded by [`TelemetryConfig::max_entries`] and
/// evicted by earliest local expiry, then key order. Rate entries are bounded
/// by the same number of origins; a single origin cannot grow either map
/// past its bound. Every time operation uses caller-supplied milliseconds.
#[derive(Debug)]
pub struct TelemetryTracker {
    config: TelemetryConfig,
    freshness: BTreeMap<TelemetryKey, Freshness>,
    rates: BTreeMap<[u8; 16], Rate>,
}

impl TelemetryTracker {
    /// Creates an empty tracker under `config`.
    #[must_use]
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            config,
            freshness: BTreeMap::new(),
            rates: BTreeMap::new(),
        }
    }

    /// Read-only policy, also exposed by the engine for hosts that need the
    /// coalescing parameters before a link is up.
    #[must_use]
    pub const fn config(&self) -> &TelemetryConfig {
        &self.config
    }

    /// Number of live freshness entries; at most `max_entries`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.freshness.len()
    }

    /// Whether no freshness entry is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.freshness.is_empty()
    }

    /// Number of origins with a rate window still open.
    #[must_use]
    pub fn origin_count(&self) -> usize {
        self.rates.len()
    }

    /// Drops freshness and rate windows that have ended by `now`.
    pub fn expire(&mut self, now: u64) {
        self.freshness.retain(|_, entry| entry.expires_at_ms > now);
        if self.config.rate_limit_ms > 0 {
            self.rates.retain(|_, rate| {
                now.saturating_sub(rate.accepted_at_ms) < self.config.rate_limit_ms
            });
        } else {
            self.rates.clear();
        }
    }

    /// Admits one update, returning the advisory to attach to its send.
    ///
    /// Order matters: stale and throttled updates fail before any state is
    /// changed, so a relay never spends a budget token on a superseded copy.
    /// A backwards clock consumes no time and can never mint a fresh window.
    pub fn admit(
        &mut self,
        now: u64,
        origin: &[u8; 16],
        kind: TelemetryKind,
        seq: u64,
        sender_lifetime_s: u64,
    ) -> Result<TelemetryAdvisory, TelemetryError> {
        let window = self.config.effective_expiry_ms(sender_lifetime_s);
        if window == 0 {
            return Err(TelemetryError::Expired);
        }
        if self.config.max_entries == 0 {
            return Err(TelemetryError::NoCapacity);
        }
        self.expire(now);
        let key = TelemetryKey {
            kind,
            origin: *origin,
        };
        if let Some(entry) = self.freshness.get(&key) {
            if seq <= entry.seq {
                return Err(TelemetryError::Stale {
                    last_seq: entry.seq,
                    seen: seq,
                });
            }
        }
        if self.config.rate_limit_ms > 0 {
            if let Some(rate) = self.rates.get(origin) {
                let elapsed = now.saturating_sub(rate.accepted_at_ms);
                if elapsed < self.config.rate_limit_ms {
                    return Err(TelemetryError::RateLimited {
                        retry_ms: self.config.rate_limit_ms - elapsed,
                    });
                }
            }
        }
        if self.freshness.len() >= self.config.max_entries {
            let victim = self
                .freshness
                .iter()
                .min_by(|(a_key, a), (b_key, b)| {
                    (a.expires_at_ms, *a_key).cmp(&(b.expires_at_ms, *b_key))
                })
                .map(|(key, _)| *key);
            if let Some(victim) = victim {
                self.freshness.remove(&victim);
            }
        }
        if self.rates.len() >= self.config.max_entries {
            let victim = self
                .rates
                .iter()
                .min_by(|(a_origin, a), (b_origin, b)| {
                    (a.accepted_at_ms, **a_origin).cmp(&(b.accepted_at_ms, **b_origin))
                })
                .map(|(origin, _)| *origin);
            if let Some(victim) = victim {
                self.rates.remove(&victim);
            }
        }
        self.freshness.insert(
            key,
            Freshness {
                seq,
                expires_at_ms: now.saturating_add(window),
            },
        );
        if self.config.rate_limit_ms > 0 {
            self.rates.insert(
                *origin,
                Rate {
                    accepted_at_ms: now,
                },
            );
        }
        Ok(TelemetryAdvisory {
            coalesce_key: coalesce_key(origin, kind),
            kind,
            seq,
            expires_in_ms: window,
            hop_limit: self.config.hop_limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: [u8; 16] = [3; 16];
    const OTHER: [u8; 16] = [4; 16];

    fn tracker() -> TelemetryTracker {
        TelemetryTracker::new(TelemetryConfig::default())
    }

    fn admit(
        tracker: &mut TelemetryTracker,
        now: u64,
        origin: &[u8; 16],
        kind: u8,
        seq: u64,
    ) -> Result<TelemetryAdvisory, TelemetryError> {
        tracker.admit(now, origin, TelemetryKind::new(kind), seq, 30)
    }

    #[test]
    fn coalesce_key_is_origin_and_kind_only() {
        let a = coalesce_key(&ORIGIN, TelemetryKind::new(7));
        assert_eq!(a, coalesce_key(&ORIGIN, TelemetryKind::new(7)));
        assert_ne!(a, coalesce_key(&OTHER, TelemetryKind::new(7)));
        assert_ne!(a, coalesce_key(&ORIGIN, TelemetryKind::new(8)));
        // The key is fixed width and domain separated from a msg_id.
        assert_eq!(a.as_bytes().len(), 16);
        let mut hasher = blake3::Hasher::new();
        hasher.update(COALESCE_DOMAIN);
        hasher.update(&ORIGIN);
        hasher.update(&[7]);
        let mut expected = [0; 16];
        expected.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        assert_eq!(a.as_bytes(), &expected);
    }

    #[test]
    fn frame_prefix_round_trips_and_rejects_malformed_input() {
        let framed = TelemetryFrame::encode(TelemetryKind::new(9), 42, b"opaque").unwrap();
        assert_eq!(framed.len(), TELEMETRY_PREFIX_LEN + 6);
        assert_eq!(framed[0], TELEMETRY_VERSION);
        let parsed = TelemetryFrame::decode(&framed).unwrap();
        assert_eq!(parsed.kind.as_u8(), 9);
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.payload, b"opaque");
        for cut in 0..TELEMETRY_PREFIX_LEN {
            assert_eq!(
                TelemetryFrame::decode(&framed[..cut]),
                Err(TelemetryError::TooShort {
                    need: TELEMETRY_PREFIX_LEN,
                    have: cut
                })
            );
        }
        let mut bad = framed;
        bad[0] = TELEMETRY_VERSION + 1;
        assert_eq!(
            TelemetryFrame::decode(&bad),
            Err(TelemetryError::UnsupportedVersion(TELEMETRY_VERSION + 1))
        );
        let too_big = vec![0; MAX_PAYLOAD];
        assert!(matches!(
            TelemetryFrame::encode(TelemetryKind::new(1), 1, &too_big),
            Err(TelemetryError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn stale_sequences_are_dropped_without_changing_rate_state() {
        let mut t = tracker();
        let first = admit(&mut t, 1_000, &ORIGIN, 7, 4).unwrap();
        assert_eq!(first.seq, 4);
        assert_eq!(
            admit(&mut t, 1_001, &ORIGIN, 7, 4),
            Err(TelemetryError::Stale {
                last_seq: 4,
                seen: 4
            })
        );
        assert_eq!(
            admit(&mut t, 1_002, &ORIGIN, 7, 3),
            Err(TelemetryError::Stale {
                last_seq: 4,
                seen: 3
            })
        );
        assert_eq!(t.origin_count(), 1);
        // The stale copies neither replaced seq 4 nor restarted the rate
        // window: the cap still ends 10 s after the first admitted update.
        assert_eq!(
            admit(&mut t, 10_000, &ORIGIN, 7, 4),
            Err(TelemetryError::Stale {
                last_seq: 4,
                seen: 4
            })
        );
        assert_eq!(
            admit(&mut t, 10_000, &ORIGIN, 7, 5),
            Err(TelemetryError::RateLimited { retry_ms: 1_000 })
        );
        // At the boundary the window has elapsed, so a newer sequence passes.
        assert_eq!(admit(&mut t, 11_000, &ORIGIN, 7, 5).unwrap().seq, 5);
    }

    #[test]
    fn rate_cap_is_per_origin_and_uses_only_local_time() {
        let mut t = tracker();
        assert!(admit(&mut t, 100, &ORIGIN, 1, 1).is_ok());
        assert_eq!(
            admit(&mut t, 200, &ORIGIN, 2, 1),
            Err(TelemetryError::RateLimited { retry_ms: 9_900 })
        );
        // A sender clock years away cannot buy an earlier window: only the
        // caller's `now` matters, and a backward step consumes no time.
        assert_eq!(
            t.admit(300, &ORIGIN, TelemetryKind::new(3), 1, u64::MAX),
            Err(TelemetryError::RateLimited { retry_ms: 9_800 })
        );
        assert!(admit(&mut t, 10_100, &ORIGIN, 2, 1).is_ok());
        assert!(admit(&mut t, 10_100, &OTHER, 1, 1).is_ok());
        assert!(
            admit(&mut t, 10_101, &ORIGIN, 1, 1).is_err(),
            "the same origin is still capped after a different kind"
        );
    }

    #[test]
    fn expiry_uses_the_local_freshness_window() {
        let mut t = tracker();
        let advisory = admit(&mut t, 10, &ORIGIN, 1, 1).unwrap();
        assert_eq!(advisory.expires_in_ms, DEFAULT_EXPIRY_MS);
        assert_eq!(advisory.hop_limit, DEFAULT_HOP_LIMIT);
        t.expire(10 + DEFAULT_EXPIRY_MS - 1);
        assert_eq!(t.len(), 1);
        t.expire(10 + DEFAULT_EXPIRY_MS);
        assert!(t.is_empty());
        // A shorter sender lifetime shortens freshness but never extends it.
        let short = t.admit(20, &ORIGIN, TelemetryKind::new(1), 2, 2).unwrap();
        assert_eq!(short.expires_in_ms, 2_000);
        assert_eq!(
            t.admit(30, &ORIGIN, TelemetryKind::new(2), 1, 30),
            Err(TelemetryError::RateLimited { retry_ms: 9_990 })
        );
        assert_eq!(
            t.admit(30, &OTHER, TelemetryKind::new(1), 1, 0),
            Err(TelemetryError::Expired)
        );
    }

    #[test]
    fn state_is_bounded_by_the_configured_entry_count() {
        let config = TelemetryConfig {
            max_entries: 2,
            rate_limit_ms: 0,
            ..TelemetryConfig::default()
        };
        let mut t = TelemetryTracker::new(config);
        // Kind distinguishes keys; the origin stays the same so only
        // freshness entries, not rate windows, can grow here.
        for (at, kind) in [(10, 1), (20, 2), (30, 3)] {
            assert!(admit(&mut t, at, &ORIGIN, kind, kind as u64).is_ok());
        }
        assert_eq!(t.len(), 2);
        assert_eq!(t.origin_count(), 0);
        // The earliest deadline was kind 1, so it was evicted.
        assert_eq!(
            admit(&mut t, 40, &ORIGIN, 1, 1),
            Ok(TelemetryAdvisory {
                coalesce_key: coalesce_key(&ORIGIN, TelemetryKind::new(1)),
                kind: TelemetryKind::new(1),
                seq: 1,
                expires_in_ms: DEFAULT_EXPIRY_MS,
                hop_limit: DEFAULT_HOP_LIMIT,
            })
        );
    }

    #[test]
    fn errors_are_typed_and_displayable() {
        let errors = [
            TelemetryError::TooShort { need: 10, have: 4 },
            TelemetryError::UnsupportedVersion(8),
            TelemetryError::PayloadTooLarge {
                len: 9_999,
                max: MAX_PAYLOAD,
            },
            TelemetryError::Expired,
            TelemetryError::Stale {
                last_seq: 2,
                seen: 1,
            },
            TelemetryError::RateLimited { retry_ms: 10 },
            TelemetryError::HopLimit,
            TelemetryError::NoCapacity,
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
}
