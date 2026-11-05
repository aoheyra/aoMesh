//! Bounded packet encoding and borrowed parsing. See `docs/protocol.md`.
//!
//! Parsing is structural, not authentication. Identity bytes stay opaque until
//! the identity and signing layers verify them; this module reads no clocks.

use core::fmt;

/// Initial packet wire version.
pub const PACKET_VERSION: u8 = 1;
/// Absolute codec payload ceiling; a link may impose a smaller frame budget.
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;
/// Largest encoded header, including an optional destination and hop fields.
pub const MAX_HEADER_LEN: usize = 72;

/// Routing class; payload contents are opaque to the codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketClass {
    /// Recipient-directed traffic.
    Direct = 0,
    /// Broadcast or channel traffic.
    Broadcast = 1,
    /// Ephemeral presence announcements.
    Presence = 2,
    /// Latest-wins telemetry.
    Telemetry = 3,
}

impl TryFrom<u8> for PacketClass {
    type Error = PacketError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Direct),
            1 => Ok(Self::Broadcast),
            2 => Ok(Self::Presence),
            3 => Ok(Self::Telemetry),
            _ => Err(PacketError::UnknownClass(value)),
        }
    }
}

/// Origin-owned fields. Encoding does not prove identity or verify signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImmutableHeader {
    /// Routing class.
    pub class: PacketClass,
    /// Reserved in version 1; must be zero.
    pub flags: u8,
    /// Opaque message identifier; derivation belongs to the signing layer.
    pub msg_id: [u8; 16],
    /// Opaque claimed origin identifier, not an authenticated `NodeId`.
    pub origin: [u8; 16],
    /// Optional claimed destination identifier.
    pub dst: Option<[u8; 16]>,
    /// Sender's time metadata, carried without wall-clock expiry decisions.
    pub created_ms: u64,
    /// Advertised lifetime in seconds; expiry policy is applied above the codec.
    pub lifetime_s: u32,
    /// Opaque payload length, bounded by [`MAX_PAYLOAD_LEN`].
    pub payload_len: u32,
}

/// Relay-owned fields, excluded from the immutable header byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopHeader {
    /// Remaining forwarding allowance; zero may still be delivered locally.
    pub ttl: u8,
    /// Hops already traversed.
    pub hops: u8,
}

/// Packet metadata with an explicit immutable/mutable split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Origin-owned metadata.
    pub immutable: ImmutableHeader,
    /// Relay-owned counters.
    pub hop: HopHeader,
}

/// A structurally checked header borrowing its immutable wire bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedHeader<'a> {
    header: Header,
    immutable_bytes: &'a [u8],
    payload_offset: usize,
}

impl<'a> ParsedHeader<'a> {
    /// Decoded metadata. The origin remains an unverified claim.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Canonical version and immutable fields, excluding both hop counters.
    ///
    /// This is a byte boundary for the signing layer, not a signature check.
    pub fn immutable_bytes(&self) -> &'a [u8] {
        self.immutable_bytes
    }

    /// Offset of the first payload byte.
    pub fn payload_offset(&self) -> usize {
        self.payload_offset
    }

    /// Required total length for exactly one complete packet.
    pub fn packet_len(&self) -> usize {
        self.payload_offset + self.header.immutable.payload_len as usize
    }
}

/// A complete packet borrowing the caller's payload buffer without allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketView<'a> {
    parsed: ParsedHeader<'a>,
    payload: &'a [u8],
}

impl<'a> PacketView<'a> {
    /// Parses exactly one packet, rejecting truncated bodies and trailing bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        let parsed = parse_header(bytes)?;
        if bytes.len() != parsed.packet_len() {
            return Err(PacketError::LengthMismatch {
                expected: parsed.packet_len(),
                actual: bytes.len(),
            });
        }
        let payload = &bytes[parsed.payload_offset..];
        Ok(Self { parsed, payload })
    }

    /// Checked header and immutable byte boundary.
    pub fn parsed_header(&self) -> &ParsedHeader<'a> {
        &self.parsed
    }

    /// Payload borrowed directly from the input, without interpreting it.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Structural wire errors; no error contains payload or identity contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketError {
    /// Header ended before a required field was complete.
    Truncated,
    /// Unsupported version byte.
    UnsupportedVersion(u8),
    /// Unsupported class byte.
    UnknownClass(u8),
    /// Nonzero reserved flags.
    UnsupportedFlags(u8),
    /// Destination marker was neither zero nor one.
    InvalidDestination(u8),
    /// Varint exceeded the destination integer's width.
    VarintOverflow,
    /// Varint used redundant leading zero groups.
    NonCanonicalVarint,
    /// Advertised payload exceeded the hard cap.
    PayloadTooLarge(u32),
    /// Declared and supplied lengths disagree.
    LengthMismatch {
        /// Required length.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// Caller-provided output is too small; it remains untouched.
    BufferTooSmall {
        /// Required capacity.
        required: usize,
        /// Supplied capacity.
        actual: usize,
    },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated packet header"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported packet version: {v}"),
            Self::UnknownClass(v) => write!(f, "unknown packet class: {v}"),
            Self::UnsupportedFlags(v) => write!(f, "unsupported packet flags: {v:#04x}"),
            Self::InvalidDestination(v) => write!(f, "invalid destination marker: {v}"),
            Self::VarintOverflow => f.write_str("packet varint overflow"),
            Self::NonCanonicalVarint => f.write_str("non-canonical packet varint"),
            Self::PayloadTooLarge(v) => write!(f, "packet payload exceeds hard cap: {v}"),
            Self::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "packet length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::BufferTooSmall { required, actual } => {
                write!(f, "packet output needs {required} bytes, got {actual}")
            }
        }
    }
}

impl core::error::Error for PacketError {}

/// Parses a complete header before inspecting or allocating a payload.
///
/// The body may be absent for streaming admission checks. Use [`PacketView::parse`]
/// before accepting a complete packet. Work is bounded by [`MAX_HEADER_LEN`].
pub fn parse_header(bytes: &[u8]) -> Result<ParsedHeader<'_>, PacketError> {
    let mut cursor = Cursor { bytes, offset: 0 };
    let version = cursor.byte()?;
    if version != PACKET_VERSION {
        return Err(PacketError::UnsupportedVersion(version));
    }
    let class = PacketClass::try_from(cursor.byte()?)?;
    let flags = cursor.byte()?;
    if flags != 0 {
        return Err(PacketError::UnsupportedFlags(flags));
    }
    let msg_id = cursor.id()?;
    let origin = cursor.id()?;
    let dst = match cursor.byte()? {
        0 => None,
        1 => Some(cursor.id()?),
        value => return Err(PacketError::InvalidDestination(value)),
    };
    let created_ms = cursor.varint(64)?;
    let lifetime_s = cursor.varint(32)? as u32;
    let payload_len = cursor.varint(32)? as u32;
    check_payload_len(payload_len)?;
    let immutable_end = cursor.offset;
    let hop = HopHeader {
        ttl: cursor.byte()?,
        hops: cursor.byte()?,
    };
    Ok(ParsedHeader {
        header: Header {
            immutable: ImmutableHeader {
                class,
                flags,
                msg_id,
                origin,
                dst,
                created_ms,
                lifetime_s,
                payload_len,
            },
            hop,
        },
        immutable_bytes: &bytes[..immutable_end],
        payload_offset: cursor.offset,
    })
}

/// Encodes a header and opaque payload into a caller-owned buffer.
///
/// Returns bytes written. All validation precedes output mutation; bytes past
/// the returned length are untouched. This function performs no allocation.
pub fn encode(header: &Header, payload: &[u8], out: &mut [u8]) -> Result<usize, PacketError> {
    let h = &header.immutable;
    if h.flags != 0 {
        return Err(PacketError::UnsupportedFlags(h.flags));
    }
    check_payload_len(h.payload_len)?;
    if h.payload_len as usize != payload.len() {
        return Err(PacketError::LengthMismatch {
            expected: h.payload_len as usize,
            actual: payload.len(),
        });
    }
    let mut scratch = [0; MAX_HEADER_LEN];
    let mut offset = 0;
    for part in [
        &[PACKET_VERSION, h.class as u8, h.flags][..],
        &h.msg_id,
        &h.origin,
    ] {
        scratch[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    scratch[offset] = u8::from(h.dst.is_some());
    offset += 1;
    if let Some(dst) = h.dst {
        scratch[offset..offset + dst.len()].copy_from_slice(&dst);
        offset += dst.len();
    }
    for value in [
        h.created_ms,
        u64::from(h.lifetime_s),
        u64::from(h.payload_len),
    ] {
        write_varint(value, &mut scratch, &mut offset);
    }
    scratch[offset..offset + 2].copy_from_slice(&[header.hop.ttl, header.hop.hops]);
    offset += 2;
    let required = offset + payload.len();
    if out.len() < required {
        return Err(PacketError::BufferTooSmall {
            required,
            actual: out.len(),
        });
    }
    out[..offset].copy_from_slice(&scratch[..offset]);
    out[offset..required].copy_from_slice(payload);
    Ok(required)
}

fn check_payload_len(value: u32) -> Result<(), PacketError> {
    if value as usize > MAX_PAYLOAD_LEN {
        Err(PacketError::PayloadTooLarge(value))
    } else {
        Ok(())
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, PacketError> {
        let value = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(PacketError::Truncated)?;
        self.offset += 1;
        Ok(value)
    }

    fn id(&mut self) -> Result<[u8; 16], PacketError> {
        let part = self
            .bytes
            .get(self.offset..self.offset + 16)
            .ok_or(PacketError::Truncated)?;
        let mut value = [0; 16];
        value.copy_from_slice(part);
        self.offset += 16;
        Ok(value)
    }

    fn varint(&mut self, bits: u32) -> Result<u64, PacketError> {
        let mut value = 0;
        for shift in (0..bits).step_by(7) {
            let byte = self.byte()?;
            let group = u64::from(byte & 0x7f);
            let remaining = bits - shift;
            if remaining < 7 && group >= (1 << remaining) {
                return Err(PacketError::VarintOverflow);
            }
            value |= group << shift;
            if byte & 0x80 == 0 {
                if shift != 0 && group == 0 {
                    return Err(PacketError::NonCanonicalVarint);
                }
                return Ok(value);
            }
        }
        Err(PacketError::VarintOverflow)
    }
}

fn write_varint(mut value: u64, out: &mut [u8; MAX_HEADER_LEN], offset: &mut usize) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        out[*offset] = byte | if value == 0 { 0 } else { 0x80 };
        *offset += 1;
        if value == 0 {
            return;
        }
    }
}
