// SPDX-License-Identifier: CC0-1.0
// SPDX-FileCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023 and 2024


/// Base64 alphabet table in [`u8`].
///
/// This table lists all Base64 alphabets as used in ssdeep.
///
/// This is the same alphabet set defined in the Table 1 of
/// [RFC 4648](https://datatracker.ietf.org/doc/rfc4648/).
pub(crate) const BASE64_TABLE_U8: [u8; 64] = [
    b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N',
    b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z',
    b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
    b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
    b'+', b'/',
];

/// Reverse byte to Base64 character index table.
///
/// This table has all 256 entries for branchless lookup, even on safe Rust.
///
/// # Performance Analysis
///
/// The original `base64_index()` function (now `tests::base64_index_simple()`)
/// did not perform well.  After profiling, we found that the old one caused
/// over 90% of parser-related branch misses.
///
/// Replacing [`base64_index()`] with the branchless implementation
/// significantly improved the parser performance.
const BASE64_REV_TABLE_U8: [u8; 256] = [
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x3e, 0x40, 0x40, 0x40, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
];

/// The constant representing an "invalid" Base64 character index.
pub(crate) const BASE64_INVALID: u8 = 0x40;

/// Tries to convert a Base64 alphabet into a corresponding index value.
///
/// If `ch` is not a valid Base64 alphabet, [`BASE64_INVALID`] is returned.
///
/// # Performance Analysis
///
/// Bound checking will not be performed on optimized settings because
/// [`BASE64_REV_TABLE_U8`] covers all possible values of [`u8`].
#[inline]
pub(crate) fn base64_index(ch: u8) -> u8 {
    BASE64_REV_TABLE_U8[ch as usize] // grcov-excl-br-line:ARRAY
}





// grcov-excl-tests-start
#[cfg(test)]
mod tests {
    use super::*;

    /// Tries to convert a Base64 alphabet into a corresponding index value.
    ///
    /// If `ch` is not a valid Base64 alphabet, [`None`] is returned.
    #[inline]
    fn base64_index_simple(ch: u8) -> Option<u8> {
        match ch {
            b'A'..=b'Z' => Some(ch - b'A'),
            b'a'..=b'z' => Some(ch - (b'a' - 26u8)),
            b'0'..=b'9' => Some(ch + (52u8 - b'0')),
            b'+' => Some(62u8),
            b'/' => Some(63u8),
            _ => None
        }
    }

    #[test]
    fn values_and_indices() {
        let mut covered_idxes = 0u64;
        let mut expected_idx = 0;
        let mut assert_base64 = |idx: usize, ch| {
            // Test indices sequentially (0..=63).
            assert!(idx < 64);
            assert_eq!(expected_idx, idx);
            assert_eq!(base64_index_simple(ch), Some(idx as u8));
            assert_eq!(BASE64_TABLE_U8[idx], ch);
            covered_idxes |= 1 << idx;
            expected_idx += 1;
        };
        assert_base64( 0, b'A');
        assert_base64( 1, b'B');
        assert_base64( 2, b'C');
        assert_base64( 3, b'D');
        assert_base64( 4, b'E');
        assert_base64( 5, b'F');
        assert_base64( 6, b'G');
        assert_base64( 7, b'H');
        assert_base64( 8, b'I');
        assert_base64( 9, b'J');
        assert_base64(10, b'K');
        assert_base64(11, b'L');
        assert_base64(12, b'M');
        assert_base64(13, b'N');
        assert_base64(14, b'O');
        assert_base64(15, b'P');
        assert_base64(16, b'Q');
        assert_base64(17, b'R');
        assert_base64(18, b'S');
        assert_base64(19, b'T');
        assert_base64(20, b'U');
        assert_base64(21, b'V');
        assert_base64(22, b'W');
        assert_base64(23, b'X');
        assert_base64(24, b'Y');
        assert_base64(25, b'Z');
        assert_base64(26, b'a');
        assert_base64(27, b'b');
        assert_base64(28, b'c');
        assert_base64(29, b'd');
        assert_base64(30, b'e');
        assert_base64(31, b'f');
        assert_base64(32, b'g');
        assert_base64(33, b'h');
        assert_base64(34, b'i');
        assert_base64(35, b'j');
        assert_base64(36, b'k');
        assert_base64(37, b'l');
        assert_base64(38, b'm');
        assert_base64(39, b'n');
        assert_base64(40, b'o');
        assert_base64(41, b'p');
        assert_base64(42, b'q');
        assert_base64(43, b'r');
        assert_base64(44, b's');
        assert_base64(45, b't');
        assert_base64(46, b'u');
        assert_base64(47, b'v');
        assert_base64(48, b'w');
        assert_base64(49, b'x');
        assert_base64(50, b'y');
        assert_base64(51, b'z');
        assert_base64(52, b'0');
        assert_base64(53, b'1');
        assert_base64(54, b'2');
        assert_base64(55, b'3');
        assert_base64(56, b'4');
        assert_base64(57, b'5');
        assert_base64(58, b'6');
        assert_base64(59, b'7');
        assert_base64(60, b'8');
        assert_base64(61, b'9');
        assert_base64(62, b'+');
        assert_base64(63, b'/');
        // Make sure that all 64 alphabets are covered.
        assert_eq!(covered_idxes, u64::MAX);
        assert_eq!(expected_idx, 64);
    }

    #[test]
    fn alphabets() {
        // Each alphabet must be unique (no duplicates in BASE64_TABLE_U8)
        let mut alphabets = std::collections::HashSet::new();
        for ch in BASE64_TABLE_U8 {
            assert!(alphabets.insert(ch));
        }
    }

    #[test]
    fn invalid_chars() {
        // Collect valid alphabets first.
        let mut alphabets = std::collections::HashSet::new();
        for ch in BASE64_TABLE_U8 {
            alphabets.insert(ch);
        }
        // If `ch` is not a Base64 alphabet,
        // base64_index for that `ch` must return None.
        for ch in u8::MIN..=u8::MAX {
            if alphabets.contains(&ch) {
                continue;
            }
            assert_eq!(base64_index_simple(ch), None);
        }
        // Invalid character has invalid index.
        assert!(BASE64_TABLE_U8.len() <= BASE64_INVALID as usize);
        // Just to make sure
        assert!(BASE64_INVALID >= 64);
    }

    #[test]
    fn compare_impls() {
        // Test that the simple implementation and
        // the branchless implementation are equivalent.
        for ch in u8::MIN..=u8::MAX {
            assert_eq!(
                base64_index(ch),
                base64_index_simple(ch).unwrap_or(BASE64_INVALID)
            );
        }
    }
}
// grcov-excl-tests-end
