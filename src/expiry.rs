//! Per-class lifetime ceilings and relative-age expiry (MSH-18).
//!
//! All local times use one monotonic epoch. Remote `created_ms` is never
//! consulted. Forwarders carry consumed age separately from signed headers;
//! this module neither changes wire fields nor authenticates age assertions.
use crate::packet::{Header, PacketClass};

/// Configurable local lifetime ceilings, in seconds.
///
/// Defaults preserve ADR-0001. Zero disables retention for that class. A local
/// ceiling may shorten the sender's lifetime but can never extend it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifetimePolicy {
    /// Direct messages: default 24 hours.
    pub direct_s: u64,
    /// Broadcast messages: default 6 hours.
    pub broadcast_s: u64,
    /// Presence messages: default 30 minutes.
    pub presence_s: u64,
    /// Telemetry freshness: default 5 minutes; telemetry is still never stored.
    pub telemetry_s: u64,
}
impl Default for LifetimePolicy {
    fn default() -> Self {
        Self {
            direct_s: 24 * 60 * 60,
            broadcast_s: 6 * 60 * 60,
            presence_s: 30 * 60,
            telemetry_s: 5 * 60,
        }
    }
}
impl LifetimePolicy {
    /// Local ceiling for a traffic class.
    pub fn lifetime_s(&self, class: PacketClass) -> u64 {
        match class {
            PacketClass::Direct => self.direct_s,
            PacketClass::Broadcast => self.broadcast_s,
            PacketClass::Presence => self.presence_s,
            PacketClass::Telemetry => self.telemetry_s,
        }
    }
    /// Time left in milliseconds, capped at `u64::MAX` for callers.
    ///
    /// `age_ms` is consumed age at receipt; `received_at` and `now` are local
    /// monotonic milliseconds. A backward clock sample consumes no additional
    /// age; callers must maintain a monotonic epoch to avoid delayed expiry.
    /// Wide arithmetic prevents overflow from expiring very long lifetimes.
    pub fn remaining_ms(&self, header: &Header, received_at: u64, age_ms: u64, now: u64) -> u64 {
        let lifetime = u128::from(header.lifetime_s.min(self.lifetime_s(header.class))) * 1000;
        let age = u128::from(age_ms) + u128::from(now.saturating_sub(received_at));
        lifetime.saturating_sub(age).min(u128::from(u64::MAX)) as u64
    }
    /// True at the exact lifetime boundary and thereafter.
    pub fn is_expired(&self, header: &Header, received_at: u64, age_ms: u64, now: u64) -> bool {
        self.remaining_ms(header, received_at, age_ms, now) == 0
    }
}

/// Consumed age to carry to the next encounter, without comparing peer clocks.
/// Saturation is conservative for the default lifetime ceilings.
/// Transport delay must be added by the caller if it is known.
pub fn age_at(received_at: u64, age_ms: u64, now: u64) -> u64 {
    age_ms.saturating_add(now.saturating_sub(received_at))
}
