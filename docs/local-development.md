# Local development with sibling crates

`ao_mesh` consumes `ao_network` and `ao_idents` from git. Until the `v0.1.0`
tags exist (MSH-31 / NET-27) the dependency points at `master`; after that
Cargo.toml pins `tag = "v0.1.0"`.

To work on the siblings together, override them locally — **never commit the
override** (AGENTS.md §8):

1. Clone the siblings side by side:

   ```text
   ~/ao/aoNetwork   ~/ao/aoMesh   ~/ao/aoIdents
   ```

2. Create `.cargo/config.toml` inside your `aoMesh` checkout (this path is
   gitignored):

   ```toml
   [patch."https://github.com/aoheyra/aoNetwork"]
   ao_network = { path = "../aoNetwork" }

   [patch."https://github.com/aoheyra/aoIdents"]
   ao_idents = { path = "../aoIdents" }
   ```

3. `cargo build` now resolves the local checkouts; `git status` stays clean.

Delete `.cargo/config.toml` (or comment out the section) to return to the
committed git dependencies. CI never sees a patch: it builds the git
dependencies exactly as pushed.
