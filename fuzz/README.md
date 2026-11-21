# Fuzz targets (MSH-28)

Three `libFuzzer` targets exercise the byte boundaries of the sans-IO core:

- `packet_decode`: header-first packet decoding, re-encoding and content-id derivation.
- `engine_input`: a verified neighbour plus arbitrary `Data`, `Tick`, `StoreSummary`, `SyncItems` and link events.
- `sync_frames`: MSH-14 v1 and MSH-15 v2 frame decoding and re-encoding.

Run them from this directory with the nightly toolchain:

```bash
cargo +nightly fuzz run packet_decode -- -max_total_time=3600 -rss_limit_mb=2048 -timeout=10 -max_len=16384
cargo +nightly fuzz run engine_input -- -max_total_time=3600 -rss_limit_mb=2048 -timeout=10 -max_len=16384
cargo +nightly fuzz run sync_frames -- -max_total_time=3600 -rss_limit_mb=2048 -timeout=10 -max_len=16384
```

The nightly `.github/workflows/fuzz.yml` runs those three commands with the
same limits and uploads crash artifacts on failure. A one-hour campaign is a CI
gate, not a local verification step.

`libfuzzer-sys`, `rand` and the sibling crates are dev-only dependencies of this
separate crate. None enter `ao_mesh`'s runtime dependency set.
