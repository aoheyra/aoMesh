# Changelog

Notable changes to `ao_mesh` are recorded here. The crate is
pre-alpha: there are no tagged releases yet, the public API may
change without notice until v0.1.0, and consumers pin by git tag
(AGENTS.md, section 8).

## Unreleased

MSH-27 adds a deterministic SimWorld harness behind feature `sim`. It drives
signed hellos, link events and the engine through the adapter across a 20-node
line, a 50-node random waypoint network, a 100-node community network and a
200-node chain with scripted contacts. `examples/sim_report` prints CSV or
writes it to a path; `tests/sim_baseline.rs` and `.github/workflows/sim.yml`
enforce directional regression bounds on delivery ratio, overhead, latency,
duplicates, radio bytes and peak queue occupancy. The adapter gains
`engine_mut` and `network_mut` so the harness can count outputs before they
are applied. Published seeds and numbers are in the README.

MSH-08 adds the baseline forwarding path for Direct. A received packet
must re-derive its content-bound `msg_id` before any state changes, is
recorded once in the seen-cache, is delivered when `dst` matches the
engine's `NodeId`, and otherwise relays to every verified neighbour
except the sending link with `ttl` decremented (the hop limit: a
submission with `ttl` N reaches N hops) and `hops` incremented,
saturating at 255. Submissions are recorded too, so no node re-relays
its own message; other classes, unverified senders and duplicates are
counted and dropped (ADR-0004, and MSH-11/19/22 own the other
classes). Delivery is structural: MSH-09 authenticates it. Tests pin
delivery without loops on a line, a ring and a seeded random graph.
Breaking unreleased API change: `MeshEngine::new` and
`MeshEngine::with_config` take the local `NodeId` after the RNG.

MSH-07 adds the signed MeshHello: the `hello` module builds, encodes,
verifies and negotiates a 161-byte fixed layout covering `node_id`,
`card_hash`, `proto`, `caps`, `store_digest` and both public keys under
`aoheyra/mesh/v1/hello`. Link-up decodes, verifies and negotiates the
peer's introduction before recording anything: a valid hello yields the
derived `NodeId` on the neighbour, an invalid, oversize or
version-incompatible one is dropped without an identity (the entry
keeps counting traffic; only a full table releases the link).
Breaking unreleased API change: `Neighbor` gained the public
`node_id: Option<NodeId>` field, and `NeighborTable::insert` is
engine-internal with new `contains`/`has_room` admission checks.

MSH-32 threads the host's monotonic network clock through the adapter:
`NetworkAdapter::handle` and `apply` take `network_now: Duration` and pass it
to every facade command that needs time (`send`, `broadcast`, `disconnect`).
Breaking unreleased API change: those two methods gained the leading
`network_now` parameter.

MSH-06 adds bounded per-link state, signed Submit commands, typed submission
errors and the optional NetworkAdapter. No runtime dependency is added.

Breaking unreleased API change: MeshInput now borrows submission identity and
payload; MeshEngine::handle returns Result<Vec<MeshOutput>, MeshError>.
Data is structurally counted, not authenticated or delivered. MSH-07/08/09
remain separate work.


Initial implementation through `MSH-05`: the sans-IO engine
interface (`MSH-01`), configuration (`MSH-02`), the v1 packet codec
(`MSH-03`), origin signatures with content-derived `msg_id` (`MSH-04`),
and the bounded forwarding seen-cache (`MSH-05`, ADR-0003).

Breaking API changes within the unreleased window: `Packet::new`
takes the origin signature, and `Header.msg_id` is a `MessageId`
rather than a raw byte array.
