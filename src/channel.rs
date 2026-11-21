//! Signed plaintext public channels (MSH-23). Subscriptions are local only.
//!
//! A versioned Broadcast body carries the channel id, origin public keys and
//! agreement binding. Every hop verifies it with aoIdents before delivery or
//! relay. Payload bytes remain opaque; channel names are exact UTF-8 bytes.
use crate::{Header, MessageId, Packet, PacketClass, sign_packet, verify_origin};
use ao_idents::{Identity, PublicIdentity, Signature, compute_node_id};
use std::collections::{BTreeMap, BTreeSet};

/// Versioned public-channel body marker, negotiated with CAP_CHANNEL_V1.
pub const CHANNEL_MAGIC: [u8; 4] = *b"AOC\x01";
pub(crate) fn is_channel(payload: &[u8]) -> bool {
    payload.starts_with(b"AOC")
}
/// Marker, channel id, two public keys, and agreement binding.
pub const CHANNEL_PREFIX_LEN: usize = 4 + 16 + 32 + 32 + 64;
/// Domain-separated, case-sensitive hash of an exact channel name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(pub [u8; 16]);
impl ChannelId {
    /// No implicit trimming or Unicode normalization is performed.
    pub fn from_name(name: &str) -> Self {
        let mut h = blake3::Hasher::new_derive_key("aoheyra/mesh/v1/channel-name");
        h.update(name.as_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&h.finalize().as_bytes()[..16]);
        Self(id)
    }
}
/// Hard memory bounds and fixed-window message limits, in addition to MSH-10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelConfig {
    /// Maximum local subscriptions.
    pub max_subscriptions: usize,
    /// Maximum active channels and origins, independently.
    pub max_entries: usize,
    /// Maximum recent accepted ids, including pending suppression windows.
    pub max_recent: usize,
    /// Local fixed-window duration. Zero disables admission.
    pub window_ms: u64,
    /// Accepted messages per channel per window.
    pub per_channel: u32,
    /// Accepted messages per origin across all channels per window.
    pub per_origin: u32,
}
impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            max_subscriptions: 64,
            max_entries: 512,
            max_recent: 4096,
            window_ms: 60_000,
            per_channel: 30,
            per_origin: 10,
        }
    }
}
/// Typed framing, authentication, or bounded policy rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// Wrong class, destination, prefix, or size.
    Malformed,
    /// Public-key binding, origin, content address, or signature is invalid.
    Authentication,
    /// A configured memory bound is exhausted.
    Capacity,
    /// A channel or origin exhausted its window allowance.
    RateLimited,
    /// This id already passed channel admission.
    Duplicate,
}
impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "channel rejected: {self:?}")
    }
}
impl std::error::Error for ChannelError {}
/// Authenticated borrowed plaintext; no payload allocation during parsing.
pub struct ChannelFrame<'a> {
    /// Exact channel identifier covered by the packet signature.
    pub channel: ChannelId,
    /// Signed, unencrypted opaque application bytes.
    pub payload: &'a [u8],
}
impl<'a> ChannelFrame<'a> {
    /// Authenticate before interpreting or exposing the application bytes.
    pub fn verify(packet: &Packet<'a>) -> Result<Self, ChannelError> {
        let p = packet.payload;
        if packet.header.class != PacketClass::Broadcast
            || packet.header.dst.is_some()
            || p.len() < CHANNEL_PREFIX_LEN
            || p.len() > crate::packet::MAX_PAYLOAD
            || !p.starts_with(&CHANNEL_MAGIC)
            || packet.header.lifetime_s == 0
        {
            return Err(ChannelError::Malformed);
        }
        let mut channel = [0; 16];
        channel.copy_from_slice(&p[4..20]);
        let mut signing = [0; 32];
        signing.copy_from_slice(&p[20..52]);
        let mut agreement = [0; 32];
        agreement.copy_from_slice(&p[52..84]);
        let mut binding = [0; 64];
        binding.copy_from_slice(&p[84..148]);
        let public = PublicIdentity::new(signing, agreement, Signature::from_bytes(binding));
        public
            .verify_binding()
            .map_err(|_| ChannelError::Authentication)?;
        if compute_node_id(&signing, &agreement).as_bytes() != &packet.header.origin {
            return Err(ChannelError::Authentication);
        }
        verify_origin(&public, &packet.header, p, &packet.signature)
            .map_err(|_| ChannelError::Authentication)?;
        Ok(Self {
            channel: ChannelId(channel),
            payload: &p[CHANNEL_PREFIX_LEN..],
        })
    }
}
/// Build a signed packet using the existing immutable-header signature domain.
pub fn encode(
    identity: &Identity,
    now: u64,
    channel: ChannelId,
    payload: &[u8],
    ttl: u8,
) -> Result<Vec<u8>, ChannelError> {
    if payload.len() > crate::packet::MAX_PAYLOAD.saturating_sub(CHANNEL_PREFIX_LEN) {
        return Err(ChannelError::Malformed);
    }
    let public = identity.public();
    let mut body = Vec::with_capacity(CHANNEL_PREFIX_LEN + payload.len());
    body.extend_from_slice(&CHANNEL_MAGIC);
    body.extend_from_slice(&channel.0);
    body.extend_from_slice(public.signing_pk());
    body.extend_from_slice(public.agreement_pk());
    body.extend_from_slice(public.agreement_binding().as_bytes());
    body.extend_from_slice(payload);
    let mut header = Header {
        class: PacketClass::Broadcast,
        dst: None,
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: now,
        lifetime_s: 21_600,
        payload_len: body.len() as u64,
        ttl,
        hops: 0,
    };
    let signature =
        sign_packet(identity, &mut header, &body).map_err(|_| ChannelError::Authentication)?;
    Ok(Packet::new(header, signature, &body)
        .map_err(|_| ChannelError::Malformed)?
        .encode())
}
#[derive(Clone, Copy)]
struct Window {
    start: u64,
    count: u32,
}
/// Bounded local subscriptions, admission windows, and delivery deduplication.
/// Full tables refuse new keys instead of evicting an origin's rate history.
pub struct ChannelTracker {
    config: ChannelConfig,
    subscriptions: BTreeSet<ChannelId>,
    channels: BTreeMap<ChannelId, Window>,
    origins: BTreeMap<[u8; 16], Window>,
    recent: BTreeMap<MessageId, u64>,
}
impl ChannelTracker {
    /// Allocate no capacity up front.
    pub fn new(config: ChannelConfig) -> Self {
        Self {
            config,
            subscriptions: BTreeSet::new(),
            channels: BTreeMap::new(),
            origins: BTreeMap::new(),
            recent: BTreeMap::new(),
        }
    }
    /// Local subscription; no membership information is sent to relays.
    pub fn subscribe(&mut self, id: ChannelId) -> Result<(), ChannelError> {
        if !self.subscriptions.contains(&id)
            && self.subscriptions.len() >= self.config.max_subscriptions
        {
            return Err(ChannelError::Capacity);
        }
        self.subscriptions.insert(id);
        Ok(())
    }
    /// Remove a local subscription.
    pub fn unsubscribe(&mut self, id: ChannelId) {
        self.subscriptions.remove(&id);
    }
    /// Whether local application delivery is enabled.
    pub fn subscribed(&self, id: ChannelId) -> bool {
        self.subscriptions.contains(&id)
    }
    /// Current bounded table sizes: subscriptions, channels, origins, recent ids.
    pub fn lengths(&self) -> (usize, usize, usize, usize) {
        (
            self.subscriptions.len(),
            self.channels.len(),
            self.origins.len(),
            self.recent.len(),
        )
    }
    /// Admit only after signature verification. Time is local monotonic time.
    pub fn admit(
        &mut self,
        now: u64,
        channel: ChannelId,
        origin: [u8; 16],
        id: MessageId,
        lifetime_s: u64,
    ) -> Result<(), ChannelError> {
        let c = self.config;
        self.channels
            .retain(|_, w| now.saturating_sub(w.start) < c.window_ms);
        self.origins
            .retain(|_, w| now.saturating_sub(w.start) < c.window_ms);
        self.recent.retain(|_, deadline| now < *deadline);
        if self.recent.contains_key(&id) {
            return Err(ChannelError::Duplicate);
        }
        if c.window_ms == 0 || c.per_channel == 0 || c.per_origin == 0 {
            return Err(ChannelError::RateLimited);
        }
        if self
            .channels
            .get(&channel)
            .is_some_and(|w| w.count >= c.per_channel)
            || self
                .origins
                .get(&origin)
                .is_some_and(|w| w.count >= c.per_origin)
        {
            return Err(ChannelError::RateLimited);
        }
        if (!self.channels.contains_key(&channel) && self.channels.len() >= c.max_entries)
            || (!self.origins.contains_key(&origin) && self.origins.len() >= c.max_entries)
            || self.recent.len() >= c.max_recent
        {
            return Err(ChannelError::Capacity);
        }
        self.channels
            .entry(channel)
            .or_insert(Window {
                start: now,
                count: 0,
            })
            .count += 1;
        self.origins
            .entry(origin)
            .or_insert(Window {
                start: now,
                count: 0,
            })
            .count += 1;
        self.recent.insert(
            id,
            now.saturating_add(lifetime_s.min(21_600).saturating_mul(1000)),
        );
        Ok(())
    }
}
