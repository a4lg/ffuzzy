# Coverage Tests with `cargo llvm-cov`

The coverage of this crate is tested by
[`cargo llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) and
[`grcov`](https://github.com/mozilla/grcov).

`cargo llvm-cov` works without any additional options.

Still, you will want to reject ignore test-related files
using following options:

```
--ignore-filename-regex '/test(s|_utils)\.rs$'
```

Since it doesn't have fine-grained exclusion control, it may mark
"expectedly" uncovered lines.  To exclude those from function coverage,
using Nightly channel and the `unstable` feature will work (it uses the
`coverage(off)` attribute).  There's no control over line and region coverage.

## Known Issues

*   Some lines of code may not be covered correctly.
