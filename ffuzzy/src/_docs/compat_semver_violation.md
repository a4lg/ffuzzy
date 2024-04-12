# Compatibility Note about SemVer Violation

This page lists all yanked versions because of SemVer-related issues:

1.  Violates SemVer compatibility (+ Rust rule about 0.x.y) itself, or
2.  Not yanking the version would result in SemVer violation on subsequent
    versions in the same version line.

## Violated Releases

*   Version 0.3.3  
    It incorrectly added unused `tests-unsound` feature and will result in
    SemVer violation on v0.3.x line if we didn't yank this version.
    Instead, the next release (version 0.3.4) removed that feature and
    yanked this release.
