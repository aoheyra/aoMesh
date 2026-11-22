use ao_mesh::{
    MessageId,
    packet::PacketClass,
    store::{conformance::entry, *},
};
use std::collections::BTreeMap;

fn id(value: u8) -> MessageId {
    MessageId::from_bytes([value; 16])
}

// Mirrors an external SQLite backend: rows own encoded bytes and local metadata
// only. `get` reconstructs an owned StoredMessage rather than lending a value
// held in this process, so no second authoritative in-memory copy is needed.
#[derive(Debug, Clone)]
struct Row {
    wire: Vec<u8>,
    metadata: StoreMetadata,
}

impl Row {
    fn message(&self) -> Option<StoredMessage> {
        StoredMessage::new(&self.wire, self.metadata).ok()
    }
}

#[derive(Debug)]
struct RowBackedStore {
    limits: StoreLimits,
    rows: BTreeMap<MessageId, Row>,
}

impl RowBackedStore {
    fn new(limits: StoreLimits) -> Self {
        Self {
            limits,
            rows: BTreeMap::new(),
        }
    }

    fn live(&self, now: u64, id: &MessageId) -> Option<StoredMessage> {
        self.rows
            .get(id)?
            .message()
            .filter(|message| !message.is_expired(now))
    }
}

impl MessageStore for RowBackedStore {
    fn put(&mut self, now: u64, entry: StoredMessage) -> Result<Vec<MessageId>, StoreError> {
        if entry.metadata().received_at > now {
            return Err(StoreError::InvalidTime);
        }
        if entry.is_expired(now) {
            return Err(StoreError::Expired);
        }
        let id = entry.header().msg_id;
        if self.live(now, &id).is_some() {
            return Err(StoreError::Duplicate);
        }
        let class = entry.header().class as usize - 1;
        if self.limits.entries == 0
            || entry.size() > self.limits.total_bytes
            || entry.size() > self.limits.per_origin_bytes
            || entry.size() > self.limits.per_class_bytes[class]
        {
            return Err(StoreError::Quota);
        }
        let mut removed = self.expire(now);
        loop {
            let total: usize = self
                .rows
                .values()
                .filter_map(|row| row.message())
                .map(|message| message.size())
                .sum();
            let origin: usize = self
                .rows
                .values()
                .filter_map(|row| row.message())
                .filter(|message| message.header().origin == entry.header().origin)
                .map(|message| message.size())
                .sum();
            let class_bytes: usize = self
                .rows
                .values()
                .filter_map(|row| row.message())
                .filter(|message| message.header().class == entry.header().class)
                .map(|message| message.size())
                .sum();
            let origin_full = origin > self.limits.per_origin_bytes - entry.size();
            let class_full = class_bytes > self.limits.per_class_bytes[class] - entry.size();
            if !origin_full
                && !class_full
                && self.rows.len() < self.limits.entries
                && total <= self.limits.total_bytes - entry.size()
            {
                break;
            }
            let victim = self
                .rows
                .iter()
                .filter_map(|(id, row)| {
                    let message = row.message()?;
                    let relieves_scope = if origin_full {
                        message.header().origin == entry.header().origin
                    } else if class_full {
                        message.header().class == entry.header().class
                    } else {
                        true
                    };
                    relieves_scope.then_some((*id, *message.metadata()))
                })
                .min_by_key(|(id, metadata)| {
                    (
                        metadata.copies_left,
                        std::cmp::Reverse(metadata.priority),
                        metadata.first_seen,
                        *id,
                    )
                })
                .map(|(id, _)| id);
            if let Some(victim) = victim {
                self.rows.remove(&victim);
                removed.push(victim);
            } else {
                break;
            }
        }
        self.rows.insert(
            id,
            Row {
                wire: entry.wire().to_vec(),
                metadata: *entry.metadata(),
            },
        );
        Ok(removed)
    }

    fn get(&self, now: u64, id: &MessageId) -> Option<StoredMessage> {
        self.live(now, id)
    }

    fn by_destination(&self, now: u64, dst: &NodeId) -> Vec<MessageId> {
        self.rows
            .iter()
            .filter_map(|(id, row)| {
                let message = row.message()?;
                (message.header().dst.as_ref() == Some(dst) && !message.is_expired(now))
                    .then_some(*id)
            })
            .collect()
    }

    fn summary(&self, now: u64) -> Vec<MessageId> {
        self.rows
            .iter()
            .filter_map(|(id, row)| {
                let message = row.message()?;
                (!message.is_expired(now)).then_some(*id)
            })
            .collect()
    }

    fn expire(&mut self, now: u64) -> Vec<MessageId> {
        let ids: Vec<_> = self
            .rows
            .iter()
            .filter_map(|(id, row)| {
                let message = row.message()?;
                message.is_expired(now).then_some(*id)
            })
            .collect();
        for id in &ids {
            self.rows.remove(id);
        }
        ids
    }

    fn evict(&mut self, id: &MessageId) -> Option<StoredMessage> {
        self.rows.remove(id).and_then(|row| row.message())
    }
}

#[test]
fn memory_backend_conformance() {
    conformance::check(MemoryStore::new);
}

#[test]
fn row_backend_conformance_with_owned_get() {
    conformance::check(RowBackedStore::new);
}

#[test]
fn owned_get_is_detached_from_row_storage() {
    let mut store = RowBackedStore::new(StoreLimits::default());
    let sample = entry(1, 1, PacketClass::Direct, 6, 1, 0);
    assert_eq!(store.put(0, sample.clone()), Ok(vec![]));
    let fetched = store.get(0, &id(1)).expect("live row");
    assert_eq!(fetched, sample);
    assert_eq!(store.evict(&id(1)), Some(sample.clone()));
    assert_eq!(fetched, sample, "owned value survives store mutation");
}

#[test]
fn eviction_priority_age_and_id_are_deterministic() {
    let mut s = MemoryStore::new(StoreLimits {
        entries: 2,
        ..StoreLimits::default()
    });
    s.put(20, entry(1, 1, PacketClass::Direct, 2, 1, 0))
        .unwrap();
    s.put(20, entry(2, 2, PacketClass::Direct, 2, 4, 20))
        .unwrap();
    assert_eq!(
        s.put(20, entry(3, 3, PacketClass::Direct, 2, 1, 20))
            .unwrap(),
        vec![id(2)]
    );
    assert_eq!(
        s.put(20, entry(4, 4, PacketClass::Direct, 2, 1, 20))
            .unwrap(),
        vec![id(1)]
    );
    assert_eq!(
        s.put(20, entry(5, 5, PacketClass::Direct, 2, 1, 20))
            .unwrap(),
        vec![id(3)]
    );
}

#[test]
fn relative_expiry_and_rejections_preserve_entries() {
    let original = entry(1, 1, PacketClass::Direct, 6, 1, 100);
    let mut meta = *original.metadata();
    meta.age_ms = 9_900;
    let aged = StoredMessage::new(original.wire(), meta).unwrap();
    assert!(!aged.is_expired(199));
    assert!(aged.is_expired(200));
    let mut s = MemoryStore::new(StoreLimits::default());
    s.put(100, original.clone()).unwrap();
    assert_eq!(
        s.put(99, entry(2, 1, PacketClass::Direct, 6, 1, 100)),
        Err(StoreError::InvalidTime)
    );
    assert_eq!(s.get(100, &id(1)), Some(original.clone()));
    assert!(matches!(
        StoredMessage::new(&vec![0; MAX_STORED_PACKET + 1], meta),
        Err(StoreError::TooLarge)
    ));
    assert!(matches!(
        StoredMessage::new(&[], meta),
        Err(StoreError::Packet(_))
    ));
    assert!(matches!(
        StoredMessage::new(&original.wire()[..original.wire().len() - 1], meta),
        Err(StoreError::Truncated)
    ));
    let mut wire = original.wire().to_vec();
    wire[1] = PacketClass::Telemetry as u8;
    assert_eq!(
        StoredMessage::new(&wire, meta),
        Err(StoreError::NotStorable)
    );
}

#[test]
fn stress_caps_and_expiry_before_live_eviction() {
    let size = entry(1, 1, PacketClass::Direct, 6, 1, 0).size();
    let mut s = MemoryStore::new(StoreLimits {
        entries: 3,
        total_bytes: size * 3,
        per_origin_bytes: size * 2,
        per_class_bytes: [size * 3; 4],
    });
    for id in 0..100u8 {
        s.put(0, entry(id, id % 3, PacketClass::Direct, 6, 1, 0))
            .unwrap();
        assert!(s.used_bytes() <= size * 3);
        assert!(s.summary(0).len() <= 3);
    }
    assert_eq!(
        s.put(10_000, entry(101, 1, PacketClass::Direct, 6, 1, 10_000))
            .unwrap()
            .len(),
        3
    );
    assert_eq!(s.summary(10_000), vec![id(101)]);
}

#[test]
fn zero_limits_and_simultaneous_scoped_pressure() {
    let size = entry(1, 1, PacketClass::Direct, 6, 1, 0).size();
    for limits in [
        StoreLimits {
            entries: 0,
            ..StoreLimits::default()
        },
        StoreLimits {
            total_bytes: 0,
            ..StoreLimits::default()
        },
        StoreLimits {
            per_origin_bytes: 0,
            ..StoreLimits::default()
        },
        StoreLimits {
            per_class_bytes: [0; 4],
            ..StoreLimits::default()
        },
    ] {
        let mut s = MemoryStore::new(limits);
        assert_eq!(
            s.put(0, entry(1, 1, PacketClass::Direct, 6, 1, 0)),
            Err(StoreError::Quota)
        );
        assert_eq!(s.used_bytes(), 0);
    }
    let mut s = MemoryStore::new(StoreLimits {
        entries: 8,
        total_bytes: size * 8,
        per_origin_bytes: size,
        per_class_bytes: [size; 4],
    });
    s.put(0, entry(1, 1, PacketClass::Broadcast, 6, 1, 0))
        .unwrap();
    s.put(0, entry(2, 2, PacketClass::Direct, 6, 1, 0)).unwrap();
    // The origin and class pressure require two disjoint evictions.
    assert_eq!(
        s.put(0, entry(3, 1, PacketClass::Direct, 6, 1, 0)).unwrap(),
        vec![id(1), id(2)]
    );
    assert_eq!(s.summary(0), vec![id(3)]);
}

#[test]
fn maximum_clock_values_and_signature_envelope_remain_bounded() {
    let base = entry(1, 1, PacketClass::Direct, 6, 1, 0);
    let mut wire = base.wire().to_vec();
    wire.extend_from_slice(&[3; 64]);
    let signed = StoredMessage::new(&wire, *base.metadata()).unwrap();
    assert_eq!(signed.wire(), wire);
    assert_eq!(signed.size(), wire.len());
    let mut meta = *base.metadata();
    meta.age_ms = u64::MAX;
    let expired = StoredMessage::new(base.wire(), meta).unwrap();
    assert!(expired.is_expired(u64::MAX));
    meta.first_seen = 1;
    assert_eq!(
        StoredMessage::new(base.wire(), meta),
        Err(StoreError::InvalidTime)
    );
}

#[test]
fn backend_errors_keep_operation_and_code_without_a_string() {
    let error = StoreError::Backend(StoreBackendError::new(
        StoreBackendOperation::Query,
        Some(5),
    ));
    assert_eq!(
        error,
        StoreError::Backend(StoreBackendError {
            operation: StoreBackendOperation::Query,
            code: Some(5),
        })
    );
    assert!(error.to_string().contains("query failed with code 5"));
}
