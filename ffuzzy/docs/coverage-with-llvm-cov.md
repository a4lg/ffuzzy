# Coverage Tests with `cargo llvm-cov`

The coverage of this crate is tested by `cargo llvm-cov` and
[`grcov`](https://github.com/mozilla/grcov).

`cargo llvm-cov` works without any additional options.

However, since it doesn't have fine-grained exclusion control, it may mark
"expectedly" uncovered lines.  To exclude those from function coverage,
using Nightly channel and the `nightly` feature will work (due to the
`coverage(off)` attribute).  There's no control over line and region coverage.

## Comparison with `grcov`

*   Unlike gcov-based `grcov`, branch coverage is not yet supported
    as of this writing.
*   Functions / methods are counted correctly.

## Known Issues

*   Some lines of code may be incorrectly uncovered.
