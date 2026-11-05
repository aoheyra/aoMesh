# ADR-0002: Borrowed packet codec

Status: proposed for MSH-03 review.

Use canonical unsigned LEB128 for variable integers and an immutable header
prefix followed by the two mutable hop counters, as specified in
[the protocol document](../protocol.md). This is the first packet version; no
previous packet layout is deployed. Future incompatible layouts require a new
version and capability negotiation through MeshHello; this codec rejects unknown
versions instead of guessing a fallback. MeshHello negotiation is separate work.

A borrowed parser and caller-owned encoding buffer avoid payload copies and
allocation on every admission path. An owned packet API would simplify storage
but allocate before the caller decides whether to accept a packet. Keeping the
hop counters adjacent at the end avoids a discontiguous signing boundary; keeping
the README's conceptual field order would require multiple immutable slices.
Neither choice changes routing, radio use or delivery policy.

The protocol document marks the previously unspecified byte assignments and hard
cap as review questions. The 1 MiB ceiling follows the link layer's hard frame
resource bound; admission still needs the smaller negotiated link budget.

The only new dependency is test-only proptest for canonical round trips and
arbitrary input. A test-only allocator wrapper measures zero allocations by
thread. Its unsafe operations only forward unchanged pointers and layouts to
System, as required by GlobalAlloc; production code forbids unsafe and uses core
only. This keeps allocation measurement independent of another test dependency.
