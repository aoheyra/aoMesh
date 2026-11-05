# Packet wire format, version 1

Proposed initial contract for MSH-03. Maintainer review must confirm the class
IDs, reserved flags, destination marker, mutable-field placement and 1 MiB hard
payload ceiling before another implementation interoperates with this codec.

The wire order is:

| Field | Encoding |
|---|---|
| version | u8, 1 |
| class | u8: Direct 0, Broadcast 1, Presence 2, Telemetry 3 |
| flags | u8, zero; all bits reserved |
| msg_id, origin | 16 opaque bytes each |
| destination marker | u8: 0 absent, 1 followed by 16 opaque destination bytes |
| created_ms | canonical unsigned LEB128, u64 |
| lifetime_s | canonical unsigned LEB128, u32 |
| payload_len | canonical unsigned LEB128, u32, at most 1,048,576 |
| ttl, hops | u8 each, relay-mutable |
| payload | exactly payload_len opaque bytes |

The immutable byte slice starts at version and ends after payload_len. The two
hop counters follow it, so forwarding cannot change that slice. MSH-04 owns
message-ID derivation, signature preimages, domain separation and verification;
the codec neither creates signatures nor authenticates origin/destination bytes.
The sibling identity crate currently exports no `NodeId` type, so the codec
carries raw claims without introducing a competing identity type.

Header parsing takes no ownership and allocates nothing, on success or failure.
It accepts a complete header without its body for admission checks; full packet
parsing requires an exact body length and rejects trailing bytes. Non-minimal,
overflowing and unterminated varints are rejected. Maximum header size is 72 B.
Unknown versions, classes, flags and destination markers fail closed.

The payload ceiling is an absolute structural bound, not a negotiated link
budget. Senders must also fit the entire packet plus link-frame overhead within
the destination link's max_frame. In particular, the default 16 KiB link cannot
carry a 1 MiB packet. Resource and fragmentation policy stay with their owners.
created_ms is carried as metadata; expiry must use the separate relative-age
policy rather than comparing different devices' wall clocks.
