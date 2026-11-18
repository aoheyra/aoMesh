# MSH-06: Engine I/O and adapter

The core owns a BTreeMap keyed by LinkId, bounded by MeshConfig.max_neighbors
(default 32, matching aoNetwork's maximum supported link configuration).
Zero refuses every link. Duplicate LinkUp preserves the existing entry;
LinkDown frees it. Counters saturate, and no unknown sender creates state.
A link bound here protects bookkeeping; aoNetwork owns radio topology.

Submit borrows Identity and payload for one synchronous call. Keeping Identity
inside the engine would simplify calls but retain keys in the wrong layer;
pre-signing in the host would move mesh packet construction outside its owner.
Borrowing keeps signing through aoIdents, with no RNG-version bridge, secret
copy or retained key. Bad submissions return typed errors before output.

The optional adapter uses standard Future/poll_fn rather than adding Tokio.
A Tokio-specific pump would provide a bundled timer but introduce a runtime
policy and dependency into a reusable layer. The host instead owns the task,
clock and timer; a Tokio task can race next_event against its deadline timer.
Timestamps are fixed for one next_event future: recreate it after a timer wakeup.
Explicit network Duration and mesh milliseconds avoid guessing their epochs.

Actions are applied synchronously with no internal asynchronous event queue.
Send failures retain their payload and link; broadcast preserves each failure.
Deliver is a host event, not a network command. It has no engine producer yet.

Data parsing is borrowed and header-first. Structural counters are not trust,
replay protection, forwarding, receipts or delivery. MSH-07/08/09 own those
policies; no routing or performance improvement is claimed by this change.
