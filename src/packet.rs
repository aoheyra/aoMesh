//! Versioned packet codec: header layout, class IDs and hard bounds.
//!
//! The wire layout (v1):
//!
//! ```text
//! offset  size        field
//! 0       1           ver (= VERSION)
//! 1       1           class (see PacketClass)
//! 2       1           flags (bit 0 = dst present; all other bits must be 0)
//! 3       16          msg_id
//! 19      16          origin
//! 35      0 or 16     dst (present iff flags bit 0 is set)
//! ..      1..10       created_ms (unsigned LEB128)
//! ..      1..10       lifetime_s (unsigned LEB128)
//! ..      1..10       payload_len (unsigned LEB128)
//! ..      1           ttl   (hop-mutable, outside the immutable prefix)
//! ..      1           hops  (hop-mutable, outside the immutable prefix)
//! ..      payload_len payload (opaque, at most MAX_PAYLOAD bytes)
//! ```
//!
//! Everything from `ver` up to (excluding) `ttl` is the **immutable prefix**:
//! one contiguous slice, so the MSH-04 origin signature covers it with a
//! single range. `ttl` and `hops` sit after the prefix and are deliberately
//! outside it: a relay decrementing `ttl` must not break verification
//! (AGENTS section 4).
//!
//! [`Header::decode`] reads only the header, never the payload bytes, and
//! allocates nothing, so a malformed or oversize packet is rejected before
//! any payload buffer exists.

use core::fmt;

/// Wire version this codec produces and the only one it accepts.
///
/// A different `ver` byte is rejected as [`PacketError::UnsupportedVersion`];
/// negotiation of future versions happens through `MeshHello.caps` (MSH-07),
/// never by silently parsing unknown bytes.
pub const VERSION: u8 = 1;

/// Size of a `msg_id` in bytes.
///
/// The value is opaque here; MSH-04 derives it from the immutable header and
/// the payload hash.
pub const MSG_ID_LEN: usize = 16;

/// Size of an origin or destination node ID in bytes.
///
/// The bytes are opaque to this crate (AGENTS section 3: `NodeId` is not
/// interpreted).
pub const NODE_ID_LEN: usize = 16;

/// Hard cap on payload bytes per packet.
///
/// 2 KiB matches the message size ADR-0001 budgets assume ("500 messages of
/// 2 KiB per hour") and fits inside aoNetwork's default 16 KiB frame with
/// room to spare, so the common packet needs no fragmentation. The cap bounds
/// per-packet relay memory before any payload byte is read.
pub const MAX_PAYLOAD: usize = 2048;

/// The four traffic classes of ADR-0001, as they appear on the wire.
///
/// Wire IDs are fixed by ADR-0002; a fifth class is a protocol change, not a
/// codec change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketClass {
    /// 1:1 traffic, spray-and-wait.
    Direct = 1,
    /// Flooded content and public channels.
    Broadcast = 2,
    /// Trickle-timed presence gossip.
    Presence = 3,
    /// Location telemetry, latest-wins.
    Telemetry = 4,
}

impl PacketClass {
    fn to_wire(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for PacketClass {
    type Error = PacketError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            1 => Ok(Self::Direct),
            2 => Ok(Self::Broadcast),
            3 => Ok(Self::Presence),
            4 => Ok(Self::Telemetry),
            other => Err(PacketError::UnknownClass(other)),
        }
    }
}

/// A typed decode or encode failure.
///
/// Every variant has a test that triggers it (`tests/packet.rs` and the
/// unit tests below); none of them panics on hostile input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// The input ends before the field at `need` bytes; `have` is the input
    /// length.
    Truncated {
        /// First byte offset that does not exist.
        need: usize,
        /// Bytes actually present.
        have: usize,
    },
    /// The `ver` byte is not [`VERSION`].
    UnsupportedVersion(u8),
    /// Class ID outside the ADR-0001 set (including the reserved 0).
    UnknownClass(u8),
    /// A flags bit other than the `dst` bit is set.
    UnknownFlags(u8),
    /// An integer was encoded with more bytes than its minimal LEB128 form.
    ///
    /// Two encodings of the same value would break `msg_id` uniqueness, so
    /// non-canonical input is rejected rather than normalised.
    NonCanonicalVarint,
    /// An integer needed more than 64 bits.
    VarintOverflow,
    /// `payload_len` exceeds [`MAX_PAYLOAD`].
    PayloadTooLarge {
        /// Declared payload length in bytes.
        len: u64,
        /// The cap, [`MAX_PAYLOAD`].
        max: u64,
    },
    /// [`Packet::new`] was given a payload whose length differs from
    /// `header.payload_len`.
    PayloadLengthMismatch {
        /// Length declared in the header.
        header: u64,
        /// Length actually supplied.
        actual: usize,
    },
    /// Bytes follow the declared payload; a packet must consume its input
    /// exactly.
    TrailingBytes {
        /// Bytes present after the payload.
        extra: usize,
    },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "input truncated: need {need} bytes, have {have}")
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported packet version {v}"),
            Self::UnknownClass(c) => write!(f, "unknown packet class {c}"),
            Self::UnknownFlags(bits) => write!(f, "unknown flag bits set: {bits:#04x}"),
            Self::NonCanonicalVarint => write!(f, "non-canonical varint encoding"),
            Self::VarintOverflow => write!(f, "varint overflows 64 bits"),
            Self::PayloadTooLarge { len, max } => {
                write!(f, "payload length {len} exceeds cap {max}")
            }
            Self::PayloadLengthMismatch { header, actual } => {
                write!(f, "payload is {actual} bytes but header says {header}")
            }
            Self::TrailingBytes { extra } => {
                write!(f, "{extra} trailing bytes after the payload")
            }
        }
    }
}

impl std::error::Error for PacketError {}

/// The hop-mutable and immutable header fields, exactly as carried on the
/// wire.
///
/// All fields are public for construction; [`Header::decode`] and
/// [`Packet::new`] enforce the version, flag, class and payload-cap rules,
/// so an encoded or decoded packet is always valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Traffic class (ADR-0001).
    pub class: PacketClass,
    /// Destination node; `None` for flooded classes.
    ///
    /// The wire flag bit is derived from this field, so "flag set but no
    /// destination" cannot be represented.
    pub dst: Option<[u8; NODE_ID_LEN]>,
    /// Message ID, opaque until MSH-04 defines its derivation.
    pub msg_id: [u8; MSG_ID_LEN],
    /// Origin node ID, opaque bytes.
    pub origin: [u8; NODE_ID_LEN],
    /// Sender timestamp in unix milliseconds; relays use relative age, never
    /// cross-device clock comparison (AGENTS section 4).
    pub created_ms: u64,
    /// How long a copy may be stored, in seconds.
    pub lifetime_s: u64,
    /// Payload length in bytes; must not exceed [`MAX_PAYLOAD`].
    pub payload_len: u64,
    /// Hop-mutable: remaining hops. Outside the immutable prefix.
    pub ttl: u8,
    /// Hop-mutable: hops already taken. Outside the immutable prefix.
    pub hops: u8,
}

impl Header {
    /// Encodes the full header (through `hops`, without payload) to a fresh
    /// buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    /// Parses the header from the front of `bytes` without reading the
    /// payload and without allocating.
    ///
    /// The payload may be absent entirely: a header that declares a valid
    /// payload length still parses, which is what makes the fast reject
    /// (AGENTS section 4) possible.
    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let mut r = Reader::new(bytes);

        let ver = r.u8()?;
        if ver != VERSION {
            return Err(PacketError::UnsupportedVersion(ver));
        }
        let class = PacketClass::try_from(r.u8()?)?;
        let flags = r.u8()?;
        if flags & !HAS_DST != 0 {
            return Err(PacketError::UnknownFlags(flags));
        }

        let msg_id = copy_array(r.take(MSG_ID_LEN)?)?;
        let origin = copy_array(r.take(NODE_ID_LEN)?)?;
        let dst = if flags & HAS_DST != 0 {
            Some(copy_array(r.take(NODE_ID_LEN)?)?)
        } else {
            None
        };

        let created_ms = r.uvarint()?;
        let lifetime_s = r.uvarint()?;
        let payload_len = r.uvarint()?;
        if payload_len > MAX_PAYLOAD as u64 {
            return Err(PacketError::PayloadTooLarge {
                len: payload_len,
                max: MAX_PAYLOAD as u64,
            });
        }

        let ttl = r.u8()?;
        let hops = r.u8()?;

        Ok(Self {
            class,
            dst,
            msg_id,
            origin,
            created_ms,
            lifetime_s,
            payload_len,
            ttl,
            hops,
        })
    }

    /// Byte length of this header on the wire (through `hops`).
    fn encoded_len(&self) -> usize {
        FIXED_PREFIX
            + if self.dst.is_some() { NODE_ID_LEN } else { 0 }
            + varint_len(self.created_ms)
            + varint_len(self.lifetime_s)
            + varint_len(self.payload_len)
            + HOP_FIELD_LEN
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(VERSION);
        out.push(self.class.to_wire());
        out.push(if self.dst.is_some() { HAS_DST } else { 0 });
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&self.origin);
        if let Some(dst) = self.dst {
            out.extend_from_slice(&dst);
        }
        put_uvarint(out, self.created_ms);
        put_uvarint(out, self.lifetime_s);
        put_uvarint(out, self.payload_len);
        out.push(self.ttl);
        out.push(self.hops);
    }
}

/// A parsed packet borrowing its payload from the input buffer.
///
/// Decoding never copies the payload, so a hostile packet costs one pass of
/// header parsing and no allocation.
///
/// ```
/// use ao_mesh::packet::{Header, Packet, PacketClass};
///
/// let header = Header {
///     class: PacketClass::Direct,
///     dst: Some([7; 16]),
///     msg_id: [1; 16],
///     origin: [2; 16],
///     created_ms: 1_700_000_000_000,
///     lifetime_s: 3_600,
///     payload_len: 4,
///     ttl: 8,
///     hops: 0,
/// };
/// let bytes = Packet::new(header, b"ping").expect("lengths agree").encode();
/// let packet = Packet::decode(&bytes).expect("round trip");
/// assert_eq!(packet.payload, b"ping");
/// assert_eq!(packet.header.ttl, 8);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    /// The decoded header.
    pub header: Header,
    /// Opaque payload bytes, borrowed from the buffer passed to
    /// [`Packet::decode`].
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Pairs a header with its payload, enforcing the cap and the
    /// length agreement between them.
    pub fn new(header: Header, payload: &'a [u8]) -> Result<Self, PacketError> {
        if header.payload_len > MAX_PAYLOAD as u64 {
            return Err(PacketError::PayloadTooLarge {
                len: header.payload_len,
                max: MAX_PAYLOAD as u64,
            });
        }
        if payload.len() as u64 != header.payload_len {
            return Err(PacketError::PayloadLengthMismatch {
                header: header.payload_len,
                actual: payload.len(),
            });
        }
        Ok(Self { header, payload })
    }

    /// Parses a complete packet: header first, then the borrowed payload.
    ///
    /// Rejects truncated input and trailing bytes; never allocates.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, PacketError> {
        let header = Header::decode(bytes)?;
        let start = header.encoded_len();
        let end = start
            .checked_add(header.payload_len as usize)
            .ok_or(PacketError::Truncated {
                need: usize::MAX,
                have: bytes.len(),
            })?;
        if bytes.len() < end {
            return Err(PacketError::Truncated {
                need: end,
                have: bytes.len(),
            });
        }
        if bytes.len() > end {
            return Err(PacketError::TrailingBytes {
                extra: bytes.len() - end,
            });
        }
        Ok(Self {
            header,
            payload: &bytes[start..end],
        })
    }

    /// Encodes header and payload into one contiguous buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header.encoded_len() + self.payload.len());
        self.header.encode_into(&mut out);
        out.extend_from_slice(self.payload);
        out
    }
}

const HAS_DST: u8 = 1 << 0;
/// `ver` + `class` + `flags` + `msg_id` + `origin`: the fixed bytes before
/// the optional `dst`.
const FIXED_PREFIX: usize = 3 + MSG_ID_LEN + NODE_ID_LEN;
const HOP_FIELD_LEN: usize = 2;

/// Cursor over a byte slice; every read is bounds-checked before it happens
/// and nothing is ever allocated.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PacketError> {
        let end = self.pos + n;
        if end > self.bytes.len() {
            return Err(PacketError::Truncated {
                need: end,
                have: self.bytes.len(),
            });
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, PacketError> {
        Ok(self.take(1)?[0])
    }

    /// Reads a canonical (minimal-form) unsigned LEB128 integer.
    fn uvarint(&mut self) -> Result<u64, PacketError> {
        let start = self.pos;
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            let bits = u64::from(byte & 0x7F);
            if shift == 63 {
                // Only the single low bit fits; anything more (or a
                // continuation) would need bit 64 and beyond.
                if bits > 1 || byte & 0x80 != 0 {
                    return Err(PacketError::VarintOverflow);
                }
                value |= bits << 63;
            } else {
                value |= bits << shift;
            }
            if byte & 0x80 == 0 {
                if self.pos - start > 1 && byte == 0 {
                    return Err(PacketError::NonCanonicalVarint);
                }
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(PacketError::VarintOverflow);
            }
        }
    }
}

/// Minimal LEB128 length of `value` (the form [`Reader`] accepts).
fn varint_len(value: u64) -> usize {
    let mut len = 1;
    let mut rest = value >> 7;
    while rest != 0 {
        len += 1;
        rest >>= 7;
    }
    len
}

/// Writes `value` in minimal (canonical) unsigned LEB128 form.
fn put_uvarint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PacketError> {
    bytes.try_into().map_err(|_| PacketError::Truncated {
        need: N,
        have: bytes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_header() -> Header {
        Header {
            class: PacketClass::Direct,
            dst: Some([9u8; NODE_ID_LEN]),
            msg_id: [1u8; MSG_ID_LEN],
            origin: [2u8; NODE_ID_LEN],
            created_ms: 1_700_000_000_000,
            lifetime_s: 3_600,
            payload_len: 0,
            ttl: 8,
            hops: 0,
        }
    }

    #[test]
    fn all_classes_round_trip() {
        for class in [
            PacketClass::Direct,
            PacketClass::Broadcast,
            PacketClass::Presence,
            PacketClass::Telemetry,
        ] {
            let mut h = base_header();
            h.class = class;
            assert_eq!(Header::decode(&h.encode()).expect("round trip"), h);
            assert_eq!(PacketClass::try_from(class.to_wire()), Ok(class));
        }
    }

    #[test]
    fn flooded_packet_has_no_dst_and_encodes_it_as_absent() {
        let mut h = base_header();
        h.dst = None;
        let bytes = h.encode();
        // flags byte sits at offset 2 and must be zero.
        assert_eq!(bytes[2], 0);
        assert_eq!(Header::decode(&bytes).expect("round trip"), h);
        // Absent dst makes the header 16 bytes shorter.
        assert_eq!(bytes.len(), base_header().encode().len() - NODE_ID_LEN);
    }

    #[test]
    fn truncated_input_is_rejected_at_every_length() {
        let bytes = base_header().encode();
        for cut in 0..bytes.len() {
            let err = Header::decode(&bytes[..cut]).expect_err("truncated");
            assert!(matches!(err, PacketError::Truncated { .. }), "{cut}: {err}");
        }
        assert!(Header::decode(&bytes).is_ok());
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = base_header().encode();
        bytes[0] = VERSION + 1;
        assert_eq!(
            Header::decode(&bytes),
            Err(PacketError::UnsupportedVersion(VERSION + 1))
        );
        bytes[0] = 0;
        assert_eq!(
            Header::decode(&bytes),
            Err(PacketError::UnsupportedVersion(0))
        );
    }

    #[test]
    fn unknown_class_is_rejected() {
        let mut bytes = base_header().encode();
        bytes[1] = 0;
        assert_eq!(Header::decode(&bytes), Err(PacketError::UnknownClass(0)));
        bytes[1] = 5;
        assert_eq!(Header::decode(&bytes), Err(PacketError::UnknownClass(5)));
    }

    #[test]
    fn unknown_flag_bits_are_rejected() {
        let mut bytes = base_header().encode();
        bytes[2] = 0x02;
        assert_eq!(Header::decode(&bytes), Err(PacketError::UnknownFlags(0x02)));
    }

    #[test]
    fn oversize_payload_len_is_rejected_by_header_only_parse() {
        let mut h = base_header();
        h.payload_len = MAX_PAYLOAD as u64 + 1;
        // Only the header exists; the reject must happen before any payload.
        let err = Header::decode(&h.encode()).expect_err("cap");
        assert_eq!(
            err,
            PacketError::PayloadTooLarge {
                len: MAX_PAYLOAD as u64 + 1,
                max: MAX_PAYLOAD as u64,
            }
        );
    }

    #[test]
    fn payload_at_the_cap_parses_header_only_without_payload_bytes() {
        let mut h = base_header();
        h.payload_len = MAX_PAYLOAD as u64;
        let parsed = Header::decode(&h.encode()).expect("header without payload");
        assert_eq!(parsed.payload_len, MAX_PAYLOAD as u64);
    }

    #[test]
    fn non_canonical_varints_are_rejected() {
        // 0 encoded as 0x80 0x00 (two bytes, trailing zero).
        let mut h = base_header();
        h.created_ms = 0;
        let mut bytes = h.encode();
        // created_ms is the first varint after the fixed prefix and dst;
        // rewrite its minimal 0x00 as the overlong pair and shift the rest.
        let at = FIXED_PREFIX + NODE_ID_LEN;
        bytes[at] = 0x80;
        bytes.insert(at + 1, 0x00);
        assert_eq!(Header::decode(&bytes), Err(PacketError::NonCanonicalVarint));
    }

    #[test]
    fn overflowing_varint_is_rejected() {
        // Eleven continuation bytes: far past 64 bits.
        let mut h = base_header();
        h.created_ms = u64::MAX;
        let mut bytes = h.encode();
        let at = FIXED_PREFIX + NODE_ID_LEN;
        let mut overlong = vec![0xFFu8; 10];
        overlong.push(0x01);
        bytes.splice(at..at + varint_len(u64::MAX), overlong);
        assert_eq!(Header::decode(&bytes), Err(PacketError::VarintOverflow));
    }

    #[test]
    fn hop_fields_are_the_only_bytes_that_differ() {
        let a = base_header();
        let mut b = base_header();
        b.ttl = a.ttl - 1;
        b.hops = a.hops + 1;
        let (a_bytes, b_bytes) = (a.encode(), b.encode());
        assert_eq!(a_bytes.len(), b_bytes.len());
        let split = a_bytes.len() - HOP_FIELD_LEN;
        assert_eq!(
            &a_bytes[..split],
            &b_bytes[..split],
            "immutable prefix must be byte-identical"
        );
        assert_ne!(&a_bytes[split..], &b_bytes[split..]);
    }

    #[test]
    fn packet_round_trip_and_lengths() {
        let mut h = base_header();
        h.payload_len = 5;
        let packet = Packet::new(h, b"ping!").expect("valid pair");
        let bytes = packet.encode();
        let decoded = Packet::decode(&bytes).expect("round trip");
        assert_eq!(decoded, packet);
        assert_eq!(decoded.payload, b"ping!");
    }

    #[test]
    fn payload_length_mismatch_is_rejected() {
        let mut h = base_header();
        h.payload_len = 4;
        assert_eq!(
            Packet::new(h, b"five!"),
            Err(PacketError::PayloadLengthMismatch {
                header: 4,
                actual: 5
            })
        );
    }

    #[test]
    fn new_rejects_oversize_payload_len() {
        let mut h = base_header();
        h.payload_len = MAX_PAYLOAD as u64 + 1;
        assert_eq!(
            Packet::new(h, &[]),
            Err(PacketError::PayloadTooLarge {
                len: MAX_PAYLOAD as u64 + 1,
                max: MAX_PAYLOAD as u64,
            })
        );
    }

    #[test]
    fn truncated_packet_is_rejected() {
        let mut h = base_header();
        h.payload_len = 4;
        let bytes = Packet::new(h, b"ping").expect("valid pair").encode();
        let err = Packet::decode(&bytes[..bytes.len() - 1]).expect_err("short");
        assert!(matches!(err, PacketError::Truncated { .. }));
        // Header alone still parses: the payload was never required.
        assert!(Header::decode(&bytes).is_ok());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let bytes = base_header().encode();
        let mut with_extra = bytes.clone();
        with_extra.push(0);
        assert_eq!(
            Packet::decode(&with_extra),
            Err(PacketError::TrailingBytes { extra: 1 })
        );
    }

    #[test]
    fn display_is_informative_for_every_variant() {
        // Formatting must not panic for any error a caller can see.
        let errors = [
            PacketError::Truncated { need: 3, have: 1 },
            PacketError::UnsupportedVersion(9),
            PacketError::UnknownClass(0),
            PacketError::UnknownFlags(0x80),
            PacketError::NonCanonicalVarint,
            PacketError::VarintOverflow,
            PacketError::PayloadTooLarge { len: 3, max: 2 },
            PacketError::PayloadLengthMismatch {
                header: 3,
                actual: 2,
            },
            PacketError::TrailingBytes { extra: 1 },
        ];
        for err in errors {
            assert!(!format!("{err}").is_empty());
        }
    }
}
