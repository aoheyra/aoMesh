# ADR: bounded MessageStore (MSH-12)

Status: proposed by issue #20 implementation.

The store trait is independent of engine I/O, routing and persistence. The app
implements SQLite and invokes `store::conformance::check` with a factory that
creates an empty backend for each supplied `StoreLimits`. The current PR tests
that suite against memory; it does not claim a SQLite implementation exists.

## Alternatives

A HashMap plus eviction heap provides faster average lookup but needs a second
index, stale-key handling and explicit tie ordering. A BTreeMap plus bounded
scans uses one owner for each entry, deterministic message-ID order and simpler
accounting. We choose the latter: O(log n) lookup, O(n) queries, and O(n^2)
worst-case insertion when all n entries must be evicted. The entry cap (1024)
bounds scans and metadata even for very small packets. This is a correctness
reference backend, not a claim of improved delivery, latency or phone battery.
SQLite can index these operations without changing their observable ordering.
No routing mechanism or routing parameter changes in this issue.

## Admission and eviction

Default encoded-byte limits: total 2 MiB, one origin 256 KiB, Direct 2 MiB,
Broadcast 512 KiB, Presence 64 KiB, Telemetry zero. These are storage resource
limits, separate from hourly relay budgets. Telemetry is never stored per
ADR-0001. Each envelope is at most MAX_PAYLOAD + 512 bytes, leaving bounded
room for routing headers and signatures. The store parses the header before
allocating and checks the declared payload is present. It does not verify
signatures or interpret the rest of the envelope; only authenticated packets
should be inserted by the delivery/forwarding pipeline.

Insertion rejects expired, future-local-time, duplicate and individually
unfittable entries before mutating the store. It then removes expired entries
in ID order. For live eviction, a violated per-origin quota is relieved first,
then per-class, then total bytes/entry count. Candidates are ordered by fewest
copies_left (most spray copies already distributed), larger priority number,
oldest first_seen, then lexicographic message ID. This interpretation is local
spray metadata, not a measurement of actual replicas on remote devices.
Admission retains the new entry; policy for refusing low-value arrivals belongs
to the forwarding layer. Evictions and insertion must be atomic in SQLite.

Metadata is not editable through borrowed references. To change spray metadata,
the caller can explicitly evict and insert an updated entry, retaining original
first_seen, received_at and age. Such multi-call changes are caller-owned and
are not an atomic metadata update API.

## Time and compatibility

All clocks passed to one store must share a monotonic local epoch. Expiry is
consumed age plus elapsed time since receipt, with saturating arithmetic;
remote created_ms never controls expiry. Restart callers must translate stored
age/time into the new epoch (MSH-29). Summary and destination queries hide
expired entries before sweeping; expire/put reclaim memory.

There is no wire-format change. Opaque envelope retention accommodates the
MSH-04 signature suffix without coupling this independent MSH-03-based PR to
the open engine adapter stack. Packet authentication remains upstream.

## Evidence

`cargo test --test store` runs backend conformance, deterministic replication /
priority / age / ID ordering, relative expiry with a remote timestamp of
u64::MAX, malformed envelopes, no-mutation rejection and a 100-insertion stress
case with byte and entry caps asserted after every insertion. APP-05 must run
the same exported conformance suite against its SQLite backend.
