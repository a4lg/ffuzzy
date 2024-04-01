# Coverage Tests with `grcov`

The coverage of this crate is tested by `cargo llvm-cov` and
[`grcov`](https://github.com/mozilla/grcov).

To use `grcov`, following options (from the surrounding workspace) are expected:

```sh
--keep-only     'ffuzzy/src/*' \
--excl-line     '// grcov-excl-line|#\[derive' \
--excl-start    '// grcov-excl(|-tests)-start' \
--excl-stop     '// grcov-excl(|-tests)-stop'  \
--excl-br-line  '// grcov-excl-br-line||#\[derive|(^| )(assert|debug_assert|invariant)!\('  \
--excl-br-start '// grcov-(excl-(br|tests)|generator)-start' \
--excl-br-stop  '// grcov-(excl-(br|tests)|generator)-stop'  \
--ignore        '*/tests.rs' \
```

It excludes generator update function from branch coverage report (due to its
heavy uses of macros).  If you need to test coverage inside those, remove
`grcov-generator-{start,stop}` lines or replace the last two lines with those.

```sh
--excl-br-start '// grcov-excl-(br|tests)-start' \
--excl-br-stop  '// grcov-excl-(br|tests)-stop'  \
```

## Known Issues

*   On function coverage, some functions are duplicated twice or more and only
    one of them are correctly counted.  This introduces the incorrect function
    count, leading to coverage result lower than the actual value.
*   On LCOV+HTML code coverage report, covered functions are not handled
    correctly, leading function coverage unreliable.
*   On branch coverage, some branches cannot be covered (e.g. matching with enum
    values, even if the enum and the match directive are exhaustive).

## Notes

*   On branch coverage, there are some cases that "not covered" case is not
    harmful.  This includes static branch inside a generic function.
