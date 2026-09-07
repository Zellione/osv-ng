# SQLCipher feasibility prototype

This Phase 1 harness opens SQLCipher with a random raw 256-bit key delivered on
the child process's stdin—not its arguments, environment, or a script file. It:

1. enables full memory security, WAL with automatic checkpointing disabled, and
   memory-only temporary storage;
2. commits a randomized plaintext canary to the catalog and a temporary table;
3. inspects database-related open descriptors and kills SQLCipher while its
   connection and WAL are live;
4. byte-scans every artifact for the canary;
5. reopens with the raw key, verifies catalog and cipher integrity, verifies
   `temp_store=MEMORY`, checkpoints, and scans again;
6. proves a wrong raw key fails without returning the canary; and
7. compares 10k-row write, query, and checkpoint wall time with SQLCipher full
   memory security enabled and disabled.

Install the exact Arch packages listed in the
[consolidated prototype prerequisites](../README.md); in particular, this uses
the system `sqlcipher` executable rather than a bundled SQLite substitute.

The output directory is required to be empty and is retained for independent
inspection. It contains only encrypted synthetic data; the ephemeral raw keys
and canary are not printed.

## Run

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo run --release
```

This is a CLI-driven integration experiment, not the Phase 5 catalog API. One
run is not a benchmark distribution. Flatpak linkage, repeated latency samples,
larger row counts, power-loss simulation, and scans of OS/library-owned memory
remain separate validation work.

## Recorded Phase 1 sample

Five host runs on 2026-09-07 each recovered cleanly after the forced crash,
passed both integrity checks, verified memory-only temp storage and wrong-key
failure, and found zero canary occurrences in disk artifacts. Median 10k-row
wall times in milliseconds were:

| Memory security | Create/write | Query | Checkpoint |
|---|---:|---:|---:|
| On | 8.45 | 6.19 | 4.29 |
| Off | 6.92 | 4.62 | 4.00 |

These short synthetic runs show direction, not a Phase 5 performance policy.
The five retained encrypted artifact directories are
`/tmp/osv-sqlcipher-repeat-1` through `-5`.
