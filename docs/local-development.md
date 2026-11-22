# Local development with sibling crates

`ao_mesh` consumes `ao_network` and `ao_idents` as untagged git sources on
their default branches. There are no release tags yet; the first release tags
start at `v0.1.0` (MSH-31 / NET-27), and all crates will adopt them together
when they are cut. Cargo treats a tagged source as a different identity from
an untagged one, so a downstream crate that depends on these siblings directly
must use the same untagged URLs as aoMesh. Otherwise the seam gets duplicate
`Identity`, `LinkId` and `NodeId` Rust types.

To work on the siblings together, override them locally — **never commit the
override** (§8):

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
