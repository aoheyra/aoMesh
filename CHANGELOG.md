# Changelog

Notable changes to `ao_mesh` are recorded here. The crate is
pre-alpha: there are no tagged releases yet, the public API may
change without notice until v0.1.0, and consumers pin by git tag
(AGENTS.md, section 8).

## Unreleased

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
