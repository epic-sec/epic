# Sealevel Attacks Benchmark

EPIC measured against [coral-xyz/sealevel-attacks](https://github.com/coral-xyz/sealevel-attacks),
pinned to commit [`24555d044802db4022112a94d6d70e74291a4b6d`](https://github.com/coral-xyz/sealevel-attacks/tree/24555d044802db4022112a94d6d70e74291a4b6d)
(2022-07-16). That repo demonstrates 11 well-known Solana/Anchor
vulnerability classes, each as three (occasionally more) hand-written
variants: `insecure`, `secure`, and `recommended`.

Pinning the commit matters because sealevel-attacks is a living teaching
repo — its fixtures can and do change. Results here are only meaningful
against this exact snapshot; re-running against `main` may show a different
picture.

## Running it

```sh
./benchmarks/sealevel/run.sh
```

This clones sealevel-attacks (or reuses `$SEALEVEL_ATTACKS_DIR` if set),
checks out the pinned commit, builds `epic` in release mode, and runs
`epic audit` against every variant of every class, printing a verdict and
findings summary per variant.

## Results

See [`RESULTS.md`](./RESULTS.md) for the full classified verdict table
(TRUE POSITIVE / FALSE NEGATIVE / FALSE POSITIVE / NOT COVERED per class)
and the reasoning behind each classification, including every known false
negative and not-covered class — this file does not hide gaps.

Regenerate the raw run with `./run.sh`; `RESULTS.md` is the classified,
narrated version of that output as of the commit noted at its top.
