# Changelog

Notable changes to `ao_mesh` are recorded here. The crate is
pre-alpha: there are no tagged releases yet, the public API may
change without notice until v0.1.0, and consumers pin by git tag
(AGENTS.md, section 8).

## Unreleased

Initial implementation through `MSH-04`: the sans-IO engine
interface (`MSH-01`), configuration (`MSH-02`), the v1 packet codec
(`MSH-03`), and origin signatures with content-derived `msg_id`
(`MSH-04`).

Breaking API changes within the unreleased window: `Packet::new`
takes the origin signature, and `Header.msg_id` is a `MessageId`
rather than a raw byte array.
