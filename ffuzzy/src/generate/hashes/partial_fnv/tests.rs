// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023–2025 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.

//! Tests: [`crate::generate::hashes::partial_fnv`].

#![cfg(test)]

use crate::test_utils::test_recommended_default;

#[cfg(not(feature = "opt-reduce-fnv-table"))]
use crate::hash::block::block_hash;
#[cfg(not(feature = "opt-reduce-fnv-table"))]
use crate::test_utils::assert_fits_in;

use super::PartialFNVHash;

#[test]
fn basic_impls() {
    test_recommended_default!(PartialFNVHash);
}

#[test]
fn initial_state() {
    assert_eq!(PartialFNVHash::new().value(), 0x27);
}

#[cfg(not(feature = "opt-reduce-fnv-table"))]
#[test]
fn table_contents() {
    const FNV_HASH_PRIME: u32 = PartialFNVHash::FNV_HASH_PRIME;
    const FNV_TABLE: [[u8; block_hash::ALPHABET_SIZE]; block_hash::ALPHABET_SIZE] =
        PartialFNVHash::FNV_TABLE;
    assert_fits_in!(block_hash::ALPHABET_SIZE, u8);
    #[inline(always)]
    fn naive_impl(state: u8, ch: u8) -> u8 {
        let state = state as u32;
        (state.wrapping_mul(FNV_HASH_PRIME) ^ (ch as u32)) as u8
    }
    for state in 0..(block_hash::ALPHABET_SIZE as u8) {
        for ch in 0..(block_hash::ALPHABET_SIZE as u8) {
            // Make sure that `FNV_TABLE` is correctly generated.
            assert_eq!(
                FNV_TABLE[state as usize][ch as usize],
                naive_impl(state, ch) % (block_hash::ALPHABET_SIZE as u8),
                "failed on state={}, ch={}",
                state,
                ch
            );
            // Of course, `FNV_TABLE` matches to masked `update_by_byte`.
            assert_eq!(
                PartialFNVHash(state).update_by_byte(ch).value(),
                naive_impl(state, ch) % (block_hash::ALPHABET_SIZE as u8),
                "failed on state={}, ch={}",
                state,
                ch
            );
        }
    }
}

#[test]
fn usage() {
    const STR: &[u8] = b"Hello, World!\n";
    const EXPECTED_HASH: u8 = 0x1e;

    // Usage: Single function call or series of calls
    // Update function 1: update_by_byte
    let mut hash = PartialFNVHash::new();
    for &ch in STR.iter() {
        hash.update_by_byte(ch);
    }
    assert_eq!(hash.value(), EXPECTED_HASH);
    // Update function 2: update_by_iter
    let mut hash = PartialFNVHash::new();
    hash.update_by_iter(STR.iter().cloned());
    assert_eq!(hash.value(), EXPECTED_HASH);
    // Update function 3: update
    let mut hash = PartialFNVHash::new();
    hash.update(STR);
    assert_eq!(hash.value(), EXPECTED_HASH);

    // Usage: Chaining (update_by_byte and folding)
    let mut hash = PartialFNVHash::new();
    let p1 = &hash as *const PartialFNVHash;
    let h = STR
        .iter()
        .fold(&mut hash, |hash, &ch| hash.update_by_byte(ch));
    let p2 = h as *const PartialFNVHash;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(h.value(), EXPECTED_HASH);
    assert_eq!(hash.value(), EXPECTED_HASH);

    // Usage: Chaining (all update functions)
    let mut hash = PartialFNVHash::new();
    let p1 = &hash as *const PartialFNVHash;
    let h = hash
        .update(b"Hello, ")
        .update_by_iter(b"World!".iter().cloned())
        .update_by_byte(b'\n');
    let p2 = h as *const PartialFNVHash;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(h.value(), EXPECTED_HASH);
    assert_eq!(hash.value(), EXPECTED_HASH);

    // Usage: Add-assign operator
    const STR_1: &[u8] = b"Hello, "; // slice
    const STR_2: &[u8; 6] = b"World!"; // array
    let mut hash = PartialFNVHash::new();
    hash += STR_1;
    hash += STR_2;
    hash += b'\n';
    assert_eq!(hash.value(), EXPECTED_HASH);
}

#[rustfmt::skip]
#[test]
fn regular_fnv1_test_vectors() {
    fn test(expected_value: u32, repetition: usize, buf: &[u8]) {
        // Overwrite the initial state with regular FNV-1-32's one (0x811c9dc5).
        // Test only the lowest 6 bits.
        let mut hash = PartialFNVHash::new();
        const FNV1_INIT: u32 = 0x811c9dc5;
        // Test update_by_byte
        hash.0 = (FNV1_INIT % (1 << 6)) as u8;
        for _ in 0..repetition {
            buf.iter().for_each(|ch| {
                hash.update_by_byte(*ch);
            });
        }
        assert_eq!(hash.value(), (expected_value % (1 << 6)) as u8);
        // Test update_by_iter
        hash.0 = (FNV1_INIT % (1 << 6)) as u8;
        for _ in 0..repetition {
            hash.update_by_iter(buf.iter().cloned());
        }
        assert_eq!(hash.value(), (expected_value % (1 << 6)) as u8);
        // Test update
        hash.0 = (FNV1_INIT % (1 << 6)) as u8;
        for _ in 0..repetition {
            hash.update(buf);
        }
        assert_eq!(hash.value(), (expected_value % (1 << 6)) as u8);
    }
    // SPDX-SnippetBegin
    // SPDX-License-Identifier: CC0-1.0
    // SPDX-SnippetCopyrightText: Authored by Tsukasa OI <floss_ssdeep@irq.a4lg.com> in 2023–2025
    // SPDX-SnippetCopyrightText: FNV-1 test vectors are based on a PD work by Landon Curt Noll, authored in 2013.
    /*
        FNV-1 test vectors below are extracted from test_fnv.c by
        Landon Curt Noll, which is in the public domain.

        <https://github.com/amutu/fnvhash/blob/42694102a9ff12eebd9c6f03861a904737c232b6/test_fnv.c>

        ========================================================================

        It follows with the original notice by the author and applies to
        this function except the `test` method above.

        Please do not copyright this code.  This code is in the public domain.

        LANDON CURT NOLL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
        INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO
        EVENT SHALL LANDON CURT NOLL BE LIABLE FOR ANY SPECIAL, INDIRECT OR
        CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
        USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
        OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
        PERFORMANCE OF THIS SOFTWARE.

        By:
            chongo <Landon Curt Noll> /\oo/\
            http://www.isthe.com/chongo/

        Share and Enjoy!    :-)

        ========================================================================

        Rust translation of the test vectors (applies to this function):

        Authored (translated) by Tsukasa OI in 2023.

        To the extent possible under law, the author(s) have dedicated all
        copyright and related and neighboring rights to this software to the
        public domain worldwide. This software is distributed without any
        warranty.

        To the extent possible under law, the person who associated CC0 with
        this function has waived all copyright and related or neighboring rights
        to this function (test_partial_fnv_hash_with_regular_fnv1_test_vector).

        You should have received a copy of the CC0 legalcode along with this
        work.  If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

        ========================================================================
    */
    test(0x811c9dc5, 1, b"");
    test(0x050c5d7e, 1, b"a");
    test(0x050c5d7d, 1, b"b");
    test(0x050c5d7c, 1, b"c");
    test(0x050c5d7b, 1, b"d");
    test(0x050c5d7a, 1, b"e");
    test(0x050c5d79, 1, b"f");
    test(0x6b772514, 1, b"fo");
    test(0x408f5e13, 1, b"foo");
    test(0xb4b1178b, 1, b"foob");
    test(0xfdc80fb0, 1, b"fooba");
    test(0x31f0b262, 1, b"foobar");
    test(0x050c5d1f, 1, b"\0");
    test(0x70772d5a, 1, b"a\0");
    test(0x6f772bc7, 1, b"b\0");
    test(0x6e772a34, 1, b"c\0");
    test(0x6d7728a1, 1, b"d\0");
    test(0x6c77270e, 1, b"e\0");
    test(0x6b77257b, 1, b"f\0");
    test(0x408f5e7c, 1, b"fo\0");
    test(0xb4b117e9, 1, b"foo\0");
    test(0xfdc80fd1, 1, b"foob\0");
    test(0x31f0b210, 1, b"fooba\0");
    test(0xffe8d046, 1, b"foobar\0");
    test(0x6e772a5c, 1, b"ch");
    test(0x4197aebb, 1, b"cho");
    test(0xfcc8100f, 1, b"chon");
    test(0xfdf147fa, 1, b"chong");
    test(0xbcd44ee1, 1, b"chongo");
    test(0x23382c13, 1, b"chongo ");
    test(0x846d619e, 1, b"chongo w");
    test(0x1630abdb, 1, b"chongo wa");
    test(0xc99e89b2, 1, b"chongo was");
    test(0x1692c316, 1, b"chongo was ");
    test(0x9f091bca, 1, b"chongo was h");
    test(0x2556be9b, 1, b"chongo was he");
    test(0x628e0e73, 1, b"chongo was her");
    test(0x98a0bf6c, 1, b"chongo was here");
    test(0xb10d5725, 1, b"chongo was here!");
    test(0xdd002f35, 1, b"chongo was here!\n");
    test(0x4197aed4, 1, b"ch\0");
    test(0xfcc81061, 1, b"cho\0");
    test(0xfdf1479d, 1, b"chon\0");
    test(0xbcd44e8e, 1, b"chong\0");
    test(0x23382c33, 1, b"chongo\0");
    test(0x846d61e9, 1, b"chongo \0");
    test(0x1630abba, 1, b"chongo w\0");
    test(0xc99e89c1, 1, b"chongo wa\0");
    test(0x1692c336, 1, b"chongo was\0");
    test(0x9f091ba2, 1, b"chongo was \0");
    test(0x2556befe, 1, b"chongo was h\0");
    test(0x628e0e01, 1, b"chongo was he\0");
    test(0x98a0bf09, 1, b"chongo was her\0");
    test(0xb10d5704, 1, b"chongo was here\0");
    test(0xdd002f3f, 1, b"chongo was here!\0");
    test(0x1c4a506f, 1, b"chongo was here!\n\0");
    test(0x6e772a41, 1, b"cu");
    test(0x26978421, 1, b"cur");
    test(0xe184ff97, 1, b"curd");
    test(0x9b5e5ac6, 1, b"curds");
    test(0x5b88e592, 1, b"curds ");
    test(0xaa8164b7, 1, b"curds a");
    test(0x20b18c7b, 1, b"curds an");
    test(0xf28025c5, 1, b"curds and");
    test(0x84bb753f, 1, b"curds and ");
    test(0x3219925a, 1, b"curds and w");
    test(0x384163c6, 1, b"curds and wh");
    test(0x54f010d7, 1, b"curds and whe");
    test(0x8cea820c, 1, b"curds and whey");
    test(0xe12ab8ee, 1, b"curds and whey\n");
    test(0x26978453, 1, b"cu\0");
    test(0xe184fff3, 1, b"cur\0");
    test(0x9b5e5ab5, 1, b"curd\0");
    test(0x5b88e5b2, 1, b"curds\0");
    test(0xaa8164d6, 1, b"curds \0");
    test(0x20b18c15, 1, b"curds a\0");
    test(0xf28025a1, 1, b"curds an\0");
    test(0x84bb751f, 1, b"curds and\0");
    test(0x3219922d, 1, b"curds and \0");
    test(0x384163ae, 1, b"curds and w\0");
    test(0x54f010b2, 1, b"curds and wh\0");
    test(0x8cea8275, 1, b"curds and whe\0");
    test(0xe12ab8e4, 1, b"curds and whey\0");
    test(0x64411eaa, 1, b"curds and whey\n\0");
    test(0x6977223c, 1, b"hi");
    test(0x428ae474, 1, b"hi\0");
    test(0xb6fa7167, 1, b"hello");
    test(0x73408525, 1, b"hello\0");
    test(0xb78320a1, 1, b"\xff\x00\x00\x01");
    test(0x0caf4135, 1, b"\x01\x00\x00\xff");
    test(0xb78320a2, 1, b"\xff\x00\x00\x02");
    test(0xcdc88e80, 1, b"\x02\x00\x00\xff");
    test(0xb78320a3, 1, b"\xff\x00\x00\x03");
    test(0x8ee1dbcb, 1, b"\x03\x00\x00\xff");
    test(0xb78320a4, 1, b"\xff\x00\x00\x04");
    test(0x4ffb2716, 1, b"\x04\x00\x00\xff");
    test(0x860632aa, 1, b"\x40\x51\x4e\x44");
    test(0xcc2c5c64, 1, b"\x44\x4e\x51\x40");
    test(0x860632a4, 1, b"\x40\x51\x4e\x4a");
    test(0x2a7ec4a6, 1, b"\x4a\x4e\x51\x40");
    test(0x860632ba, 1, b"\x40\x51\x4e\x54");
    test(0xfefe8e14, 1, b"\x54\x4e\x51\x40");
    test(0x0a3cffd8, 1, b"127.0.0.1");
    test(0xf606c108, 1, b"127.0.0.1\0");
    test(0x0a3cffdb, 1, b"127.0.0.2");
    test(0xf906c5c1, 1, b"127.0.0.2\0");
    test(0x0a3cffda, 1, b"127.0.0.3");
    test(0xf806c42e, 1, b"127.0.0.3\0");
    test(0xc07167d7, 1, b"64.81.78.68");
    test(0xc9867775, 1, b"64.81.78.68\0");
    test(0xbf716668, 1, b"64.81.78.74");
    test(0xc78435b8, 1, b"64.81.78.74\0");
    test(0xc6717155, 1, b"64.81.78.84");
    test(0xb99568cf, 1, b"64.81.78.84\0");
    test(0x7662e0d6, 1, b"feedface");
    test(0x33a7f0e2, 1, b"feedface\0");
    test(0xc2732f95, 1, b"feedfacedaffdeed");
    test(0xb053e78f, 1, b"feedfacedaffdeed\0");
    test(0x3a19c02a, 1, b"feedfacedeadbeef");
    test(0xa089821e, 1, b"feedfacedeadbeef\0");
    test(0x31ae8f83, 1, b"line 1\nline 2\nline 3");
    test(0x995fa9c4, 1, b"chongo <Landon Curt Noll> /\\../\\");
    test(0x35983f8c, 1, b"chongo <Landon Curt Noll> /\\../\\\0");
    test(0x5036a251, 1, b"chongo (Landon Curt Noll) /\\../\\");
    test(0x97018583, 1, b"chongo (Landon Curt Noll) /\\../\\\0");
    test(0xb4448d60, 1, b"http://antwrp.gsfc.nasa.gov/apod/astropix.html");
    test(0x025dfe59, 1, b"http://en.wikipedia.org/wiki/Fowler_Noll_Vo_hash");
    test(0xc5eab3af, 1, b"http://epod.usra.edu/");
    test(0x7d21ba1e, 1, b"http://exoplanet.eu/");
    test(0x7704cddb, 1, b"http://hvo.wr.usgs.gov/cam3/");
    test(0xd0071bfe, 1, b"http://hvo.wr.usgs.gov/cams/HMcam/");
    test(0x0ff3774c, 1, b"http://hvo.wr.usgs.gov/kilauea/update/deformation.html");
    test(0xb0fea0ea, 1, b"http://hvo.wr.usgs.gov/kilauea/update/images.html");
    test(0x58177303, 1, b"http://hvo.wr.usgs.gov/kilauea/update/maps.html");
    test(0x4f599cda, 1, b"http://hvo.wr.usgs.gov/volcanowatch/current_issue.html");
    test(0x3e590a47, 1, b"http://neo.jpl.nasa.gov/risk/");
    test(0x965595f8, 1, b"http://norvig.com/21-days.html");
    test(0xc37f178d, 1, b"http://primes.utm.edu/curios/home.php");
    test(0x9711dd26, 1, b"http://slashdot.org/");
    test(0x23c99b7f, 1, b"http://tux.wr.usgs.gov/Maps/155.25-19.5.html");
    test(0x6e568b17, 1, b"http://volcano.wr.usgs.gov/kilaueastatus.php");
    test(0x43f0245b, 1, b"http://www.avo.alaska.edu/activity/Redoubt.php");
    test(0xbcb7a001, 1, b"http://www.dilbert.com/fast/");
    test(0x12e6dffe, 1, b"http://www.fourmilab.ch/gravitation/orbits/");
    test(0x0792f2d6, 1, b"http://www.fpoa.net/");
    test(0xb966936b, 1, b"http://www.ioccc.org/index.html");
    test(0x46439ac5, 1, b"http://www.isthe.com/cgi-bin/number.cgi");
    test(0x728d49af, 1, b"http://www.isthe.com/chongo/bio.html");
    test(0xd33745c9, 1, b"http://www.isthe.com/chongo/index.html");
    test(0xbc382a57, 1, b"http://www.isthe.com/chongo/src/calc/lucas-calc");
    test(0x4bda1d31, 1, b"http://www.isthe.com/chongo/tech/astro/venus2004.html");
    test(0xce35ccae, 1, b"http://www.isthe.com/chongo/tech/astro/vita.html");
    test(0x3b6eed94, 1, b"http://www.isthe.com/chongo/tech/comp/c/expert.html");
    test(0x445c9c58, 1, b"http://www.isthe.com/chongo/tech/comp/calc/index.html");
    test(0x3db8bf9d, 1, b"http://www.isthe.com/chongo/tech/comp/fnv/index.html");
    test(0x2dee116d, 1, b"http://www.isthe.com/chongo/tech/math/number/howhigh.html");
    test(0xc18738da, 1, b"http://www.isthe.com/chongo/tech/math/number/number.html");
    test(0x5b156176, 1, b"http://www.isthe.com/chongo/tech/math/prime/mersenne.html");
    test(0x2aa7d593, 1, b"http://www.isthe.com/chongo/tech/math/prime/mersenne.html#largest");
    test(0xb2409658, 1, b"http://www.lavarnd.org/cgi-bin/corpspeak.cgi");
    test(0xe1489528, 1, b"http://www.lavarnd.org/cgi-bin/haiku.cgi");
    test(0xfe1ee07e, 1, b"http://www.lavarnd.org/cgi-bin/rand-none.cgi");
    test(0xe8842315, 1, b"http://www.lavarnd.org/cgi-bin/randdist.cgi");
    test(0x3a6a63a2, 1, b"http://www.lavarnd.org/index.html");
    test(0x06d2c18c, 1, b"http://www.lavarnd.org/what/nist-test.html");
    test(0xf8ef7225, 1, b"http://www.macosxhints.com/");
    test(0x843d3300, 1, b"http://www.mellis.com/");
    test(0xbb24f7ae, 1, b"http://www.nature.nps.gov/air/webcams/parks/havoso2alert/havoalert.cfm");
    test(0x878c0ec9, 1, b"http://www.nature.nps.gov/air/webcams/parks/havoso2alert/timelines_24.cfm");
    test(0xb557810f, 1, b"http://www.paulnoll.com/");
    test(0x57423246, 1, b"http://www.pepysdiary.com/");
    test(0x87f7505e, 1, b"http://www.sciencenews.org/index/home/activity/view");
    test(0xbb809f20, 1, b"http://www.skyandtelescope.com/");
    test(0x8932abb5, 1, b"http://www.sput.nl/~rob/sirius.html");
    test(0x0a9b3aa0, 1, b"http://www.systemexperts.com/");
    test(0xb8682a24, 1, b"http://www.tq-international.com/phpBB3/index.php");
    test(0xa7ac1c56, 1, b"http://www.travelquesttours.com/index.htm");
    test(0x11409252, 1, b"http://www.wunderground.com/global/stations/89606.html");
    // Repeated by 10
    test(0xa987f517, 10, b"21701");
    test(0xf309e7ed, 10, b"M21701");
    test(0xc9e8f417, 10, b"2^21701-1");
    test(0x7f447bdd, 10, b"\x54\xc5");
    test(0xb929adc5, 10, b"\xc5\x54");
    test(0x57022879, 10, b"23209");
    test(0xdcfd2c49, 10, b"M23209");
    test(0x6edafff5, 10, b"2^23209-1");
    test(0xf04fb1f1, 10, b"\x5a\xa9");
    test(0xfb7de8b9, 10, b"\xa9\x5a");
    test(0xc5f1d7e9, 10, b"391581216093");
    test(0x32c1f439, 10, b"391581*2^216093-1");
    test(0x7fd3eb7d, 10, b"\x05\xf9\x9d\x03\x4c\x81");
    test(0x81597da5, 10, b"FEDCBA9876543210");
    test(0x05eb7a25, 10, b"\xfe\xdc\xba\x98\x76\x54\x32\x10");
    test(0x9c0fa1b5, 10, b"EFCDAB8967452301");
    test(0x53ccb1c5, 10, b"\xef\xcd\xab\x89\x67\x45\x23\x01");
    test(0xfabece15, 10, b"0123456789ABCDEF");
    test(0x4ad745a5, 10, b"\x01\x23\x45\x67\x89\xab\xcd\xef");
    test(0xe5bdc495, 10, b"1032547698BADCFE");
    test(0x23b3c0a5, 10, b"\x10\x32\x54\x76\x98\xba\xdc\xfe");
    // Repeated by 500
    test(0xfa823dd5, 500, b"\x00");
    test(0x0c6c58b9, 500, b"\x07");
    test(0xe2dbccd5, 500, b"~");
    test(0xdb7f50f9, 500, b"\x7f");
    // SPDX-SnippetEnd
}
