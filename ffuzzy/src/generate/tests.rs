// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2023 Tsukasa OI <floss_ssdeep@irq.a4lg.com>.
// grcov-excl-br-start

#![cfg(test)]

use core::str::FromStr;
#[cfg(feature = "alloc")]
use alloc::format;
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256StarStar;
use crate::generate::{
    PartialFNVHash, RollingHash, BlockHashContext,
    Generator, GeneratorError
};
use crate::hash::FuzzyHashData;
use crate::hash::RawFuzzyHash;
use crate::hash::block::{BlockSize, BlockHash};
use crate::test_utils::{cover_auto_clone, cover_default, test_auto_clone, test_recommended_default};
#[cfg(feature = "alloc")]
use crate::test_utils::test_auto_debug_for_enum;


#[test]
fn test_partial_fnv_hash_basic() {
    test_recommended_default!(PartialFNVHash);
    test_auto_clone::<PartialFNVHash>(&PartialFNVHash::new());
}

#[test]
fn test_partial_fnv_hash_initial() {
    assert_eq!(PartialFNVHash::new().value(), 0x27);
}

#[test]
fn test_partial_fnv_hash_usage() {
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
    let h = STR.iter()
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
}

#[cfg(feature = "alloc")]
#[test]
fn test_partial_fnv_hash_debug() {
    // 39 == 0x27 == the lowest 6 bits of 0x28021967
    assert_eq!(
        format!("{:?}", PartialFNVHash::new()),
        "PartialFNVHash(39)"
    );
}

#[test]
fn test_partial_fnv_hash_with_regular_fnv1_test_vector() {
    fn test(expected_value: u32, repetition: usize, buf: &[u8]) {
        // Overwrite the initial state with regular FNV-1-32's one (0x811c9dc5).
        // Test only the lowest 6 bits.
        let mut hash = PartialFNVHash::new();
        const FNV1_INIT: u32 = 0x811c9dc5;
        // Test update_by_byte
        hash.0 = (FNV1_INIT % (1 << 6)) as u8;
        for _ in 0..repetition {
            buf.iter().for_each(|ch| { hash.update_by_byte(*ch); });
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
}


#[test]
fn test_rolling_hash_basic() {
    test_recommended_default!(RollingHash);
    test_auto_clone::<RollingHash>(&RollingHash::new());
}

#[test]
fn test_rolling_hash_usage() {
    const STR: &[u8] = b"Hello, World!\n";
    const EXPECTED_HASH: u32 = 0x19179d98;

    // Usage: Single function call or series of calls
    // Update function 1: update_by_byte
    let mut hash = RollingHash::new();
    for &ch in STR.iter() {
        hash.update_by_byte(ch);
    }
    assert_eq!(hash.value(), EXPECTED_HASH);
    // Update function 2: update_by_iter
    let mut hash = RollingHash::new();
    hash.update_by_iter(STR.iter().cloned());
    assert_eq!(hash.value(), EXPECTED_HASH);
    // Update function 3: update
    let mut hash = RollingHash::new();
    hash.update(STR);
    assert_eq!(hash.value(), EXPECTED_HASH);

    // Usage: Chaining (update_by_byte and folding)
    let mut hash = RollingHash::new();
    let p1 = &hash as *const RollingHash;
    let h = STR.iter()
        .fold(&mut hash, |hash, &ch| hash.update_by_byte(ch));
    let p2 = h as *const RollingHash;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(h.value(), EXPECTED_HASH);
    assert_eq!(hash.value(), EXPECTED_HASH);

    // Usage: Chaining (all update functions)
    let mut hash = RollingHash::new();
    let p1 = &hash as *const RollingHash;
    let h = hash
        .update(b"Hello, ")
        .update_by_iter(b"World!".iter().cloned())
        .update_by_byte(b'\n');
    let p2 = h as *const RollingHash;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(h.value(), EXPECTED_HASH);
    assert_eq!(hash.value(), EXPECTED_HASH);
}

#[cfg(feature = "alloc")]
#[test]
fn test_rolling_hash_debug() {
    assert_eq!(
        format!("{:?}", RollingHash::new()),
        "RollingHash { \
            index: 0, \
            h1: 0, \
            h2: 0, \
            h3: 0, \
            window: [0, 0, 0, 0, 0, 0, 0] \
        }"
    );
}

#[test]
fn test_rolling_hash_rolling_basic() {
    // h2_multiplier := 1+2+...+WINDOW_SIZE
    let mut h2_multiplier = 0u32;
    for i in 0..RollingHash::WINDOW_SIZE {
        h2_multiplier += (i as u32) + 1;
    }
    // Check rolling hash internals by supplying WINDOW_SIZE bytes
    let mut hash = RollingHash::new();
    // Repeating the process should not change the result.
    for _ in 0..2 {
        for ch in u8::MIN..=u8::MAX {
            for _ in 0..RollingHash::WINDOW_SIZE {
                hash.update_by_byte(ch);
            }
            // h1: Plain sum
            assert_eq!(hash.h1, (ch as u32) * (RollingHash::WINDOW_SIZE as u32));
            // h2: Weighted sum
            assert_eq!(hash.h2, (ch as u32) * h2_multiplier);
            // h3: shift-xor
            let mut h3_expected = 0u32;
            for _ in 0..RollingHash::WINDOW_SIZE {
                h3_expected <<= RollingHash::H3_LSHIFT;
                h3_expected ^= ch as u32;
            }
            assert_eq!(hash.h3, h3_expected);
        }
    }
}

fn fuzz_rolling_hash_rolling_random_with_config(num_iterations: usize, random_seed: u64) {
    // [0]: fading byte, [RollingHash::WINDOW_SIZE-1]: last (the most weighted) byte
    let mut last_bytes = [0u8; RollingHash::WINDOW_SIZE];
    let mut rng = Xoshiro256StarStar::seed_from_u64(random_seed);
    let mut hash = RollingHash::new();
    for _ in 0..num_iterations {
        for i in 1..RollingHash::WINDOW_SIZE {
            last_bytes[i - 1] = last_bytes[i];
        }
        let last_ch = rng.gen();
        last_bytes[last_bytes.len() - 1] = last_ch;
        hash.update_by_byte(last_ch);
        // h1: Plain sum
        let h1_expected = last_bytes[..].iter().fold(0u32, |acc, &x| acc + (x as u32));
        assert_eq!(hash.h1, h1_expected);
        // h2: Weighted sum
        let mut h2_expected = 0u32;
        for (i, &ch) in last_bytes[..].iter().enumerate() {
            h2_expected += ((i as u32) + 1) * (ch as u32);
        }
        assert_eq!(hash.h2, h2_expected);
        // h3: shift-xor
        let mut h3_expected = 0u32;
        for &ch in last_bytes[..].iter() {
            h3_expected <<= RollingHash::H3_LSHIFT;
            h3_expected ^= ch as u32;
        }
        assert_eq!(hash.h3, h3_expected);
        // value: h1+h2+h3
        assert_eq!(hash.value(), h1_expected.wrapping_add(h2_expected).wrapping_add(h3_expected));
    }
}

#[test]
fn fuzz_rolling_hash_rolling_random() {
    const NUM_ITERATIONS: usize = 1_000_000;
    const RANDOM_SEED: u64 = 0x4d75_bf08_e0e0_9e73;
    fuzz_rolling_hash_rolling_random_with_config(NUM_ITERATIONS, RANDOM_SEED);
}

#[cfg(feature = "tests-slow")]
#[test]
fn fuzz_rolling_hash_rolling_random_slow() {
    const NUM_ITERATIONS: usize = 1_000_000_000;
    const RANDOM_SEED: u64 = 0x2bd9_2c64_308b_e2ed;
    fuzz_rolling_hash_rolling_random_with_config(NUM_ITERATIONS, RANDOM_SEED);
}


#[test]
fn test_block_hash_context_basic() {
    cover_auto_clone::<BlockHashContext>(&BlockHashContext::new());
}

#[cfg(feature = "alloc")]
#[test]
fn test_block_hash_context_debug() {
    // 39 == 0x27 == the lowest 6 bits of 0x28021967
    // 255 == BLOCKHASH_CHAR_NIL
    assert_eq!(
        format!("{:?}", BlockHashContext::new()),
        "BlockHashContext { \
            blockhash_index: 0, \
            blockhash: [\
                255, 255, 255, 255, 255, 255, 255, 255, \
                255, 255, 255, 255, 255, 255, 255, 255, \
                255, 255, 255, 255, 255, 255, 255, 255, \
                255, 255, 255, 255, 255, 255, 255, 255, \
                255, 255, 255, 255, 255, 255, 255, 255, \
                255, 255, 255, 255, 255, 255, 255, 255, \
                255, 255, 255, 255, 255, 255, 255, 255, \
                255, 255, 255, 255, 255, 255, 255, 255\
            ], \
            blockhash_ch_half: 255, \
            h_full: PartialFNVHash(39), \
            h_half: PartialFNVHash(39) \
        }"
    );
}


macro_rules! test_for_each_generator_finalization {
    ($test: ident) => {
        { $test!(false, {BlockHash::FULL_SIZE}, {BlockHash::FULL_SIZE}); }
        { $test!(false, {BlockHash::FULL_SIZE}, {BlockHash::HALF_SIZE}); }
        { $test!(true,  {BlockHash::FULL_SIZE}, {BlockHash::FULL_SIZE}); }
        { $test!(true,  {BlockHash::FULL_SIZE}, {BlockHash::HALF_SIZE}); }
    };
}

#[test]
fn test_generator_error_basic() {
    #[cfg(feature = "alloc")]
    {
        test_auto_debug_for_enum!(
            GeneratorError,
            [
                FixedSizeMismatch,
                FixedSizeTooLarge,
                InputSizeTooLarge,
                OutputOverflow,
            ]
        );
    }
    test_auto_clone::<GeneratorError>(&GeneratorError::FixedSizeMismatch);
}

#[cfg(feature = "alloc")]
#[test]
fn test_generator_error_display() {
    assert_eq!(format!("{}", GeneratorError::FixedSizeMismatch),
        "current state mismatches to the fixed size previously set.");
    assert_eq!(format!("{}", GeneratorError::FixedSizeTooLarge),
        "fixed size is too large to generate a fuzzy hash.");
    assert_eq!(format!("{}", GeneratorError::InputSizeTooLarge),
        "input size is too large to generate a fuzzy hash.");
    assert_eq!(format!("{}", GeneratorError::OutputOverflow),
        "output is too large for specific fuzzy hash variant.");
}

#[test]
fn test_generator_error_is_size_too_large_error() {
    assert!(!GeneratorError::FixedSizeMismatch.is_size_too_large_error());
    assert!(!GeneratorError::OutputOverflow.is_size_too_large_error());
    assert!(GeneratorError::FixedSizeTooLarge.is_size_too_large_error());
    assert!(GeneratorError::InputSizeTooLarge.is_size_too_large_error());
}


#[test]
fn cover_generator_basic() {
    cover_default::<Generator>();
    cover_auto_clone::<Generator>(&Generator::new());
}

#[cfg(feature = "alloc")]
#[test]
fn test_generator_debug() {
    // Make expected bh_context output dynamically.
    // format!("{:?}", BlockHashContext::new()) is tested by
    // test_block_hash_context_debug above.
    let s = core::iter::repeat(format!("{:?}", BlockHashContext::new()).as_str())
        .take(BlockSize::NUM_VALID).collect::<alloc::vec::Vec<&str>>().join(", ");
    // Test the generator
    assert_eq!(
        format!("{:?}", Generator::new()),
        format!("Generator {{ \
            input_size: 0, \
            fixed_size: None, \
            elim_border: 192, \
            bhidx_start: 0, \
            bhidx_end: 1, \
            bhidx_end_limit: 30, \
            roll_mask: 0, \
            roll_hash: RollingHash {{ index: 0, h1: 0, h2: 0, h3: 0, window: [0, 0, 0, 0, 0, 0, 0] }}, \
            bh_context: [{}], \
            h_last: PartialFNVHash(39), \
            is_last: false \
        }}", s)
    );
}

#[test]
fn test_generator_empty() {
    let mut generator = Generator::new();
    generator.set_fixed_input_size(0).unwrap();
    assert!(generator.may_warn_about_small_input_size());
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        type FuzzyHashType = FuzzyHashData<$bs1, $bs2, false>;
        let hash = generator.finalize_raw::<$trunc, $bs1, $bs2>().unwrap();
        assert_eq!(hash.block_size(), BlockSize::MIN);
        assert_eq!(hash.block_hash_1_len(), 0);
        assert_eq!(hash.block_hash_2_len(), 0);
        let hash_expected = FuzzyHashType::from_str("3::").unwrap();
        assert_eq!(hash, hash_expected);
    }}
    test_for_each_generator_finalization!(test);
}

#[test]
fn test_generator_usage() {
    const STR: &[u8] = b"Hello, World!\n";
    let expected_hash = RawFuzzyHash::from_str("3:aaX8v:aV").unwrap();

    // Usage: Single function call or series of calls
    // Update function 1: update_by_byte
    let mut generator = Generator::new();
    for &ch in STR.iter() {
        generator.update_by_byte(ch);
    }
    assert_eq!(generator.finalize().unwrap(), expected_hash);
    // Update function 2: update_by_iter
    let mut generator = Generator::new();
    generator.update_by_iter(STR.iter().cloned());
    assert_eq!(generator.finalize().unwrap(), expected_hash);
    // Update function 3: update
    let mut generator = Generator::new();
    generator.update(STR);
    assert_eq!(generator.finalize().unwrap(), expected_hash);

    // Usage: Chaining (update_by_byte and folding)
    let mut generator = Generator::new();
    let p1 = &generator as *const Generator;
    let h = STR.iter()
        .fold(&mut generator, |hash, &ch| hash.update_by_byte(ch));
    let p2 = h as *const Generator;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(h.finalize().unwrap(), expected_hash);
    assert_eq!(generator.finalize().unwrap(), expected_hash);

    // Usage: Chaining (all update functions)
    let mut generator = Generator::new();
    let p1 = &generator as *const Generator;
    let h = generator
        .update(b"Hello, ")
        .update_by_iter(b"World!".iter().cloned())
        .update_by_byte(b'\n');
    let p2 = h as *const Generator;
    assert_eq!(p1, p2); // check if we are operating with the same object.
    assert_eq!(h.finalize().unwrap(), expected_hash);
    assert_eq!(generator.finalize().unwrap(), expected_hash);
}

#[test]
fn test_get_log_block_size_from_input_size() {
    // Compare behavior with the naïve implementation.
    fn get_log_block_size_from_input_size_naive(size: u64, start: usize) -> usize {
        let mut log_block_size = start;
        let mut max_guessed_size = Generator::guessed_preferred_max_input_size_at(log_block_size as u8);
        while max_guessed_size < size {
            log_block_size    += 1;
            max_guessed_size *= 2;
        }
        log_block_size
    }
    for i in 0..BlockSize::NUM_VALID {
        let size = Generator::guessed_preferred_max_input_size_at(i as u8);
        for j in 0..BlockSize::NUM_VALID {
            assert_eq!(
                get_log_block_size_from_input_size_naive(size - 2, j),
                Generator::get_log_block_size_from_input_size(size - 2, j)
            );
            assert_eq!(
                get_log_block_size_from_input_size_naive(size - 1, j),
                Generator::get_log_block_size_from_input_size(size - 1, j)
            );
            assert_eq!(
                get_log_block_size_from_input_size_naive(size, j),
                Generator::get_log_block_size_from_input_size(size, j)
            );
            if size + 1 <= Generator::MAX_INPUT_SIZE {
                assert_eq!(
                    get_log_block_size_from_input_size_naive(size + 1, j),
                    Generator::get_log_block_size_from_input_size(size + 1, j)
                );
            }
            if size + 2 <= Generator::MAX_INPUT_SIZE {
                assert_eq!(
                    get_log_block_size_from_input_size_naive(size + 2, j),
                    Generator::get_log_block_size_from_input_size(size + 2, j)
                );
            }
        }
    }
}

#[test]
fn test_usage_fixed_size() {
    let mut generator = Generator::new();
    // Set the fixed size.
    assert_eq!(generator.set_fixed_input_size(100), Ok(()));
    // Set the same fixed size.
    assert_eq!(generator.set_fixed_input_size(100), Ok(()));
    // Setting the different size will result in the error.
    assert_eq!(generator.set_fixed_input_size(999), Err(GeneratorError::FixedSizeMismatch));
    // Generator::MAX_INPUT_SIZE is inclusive (but MAX_INPUT_SIZE+1 is not valid).
    let mut generator = Generator::new();
    assert_eq!(generator.set_fixed_input_size(Generator::MAX_INPUT_SIZE), Ok(()));
    let mut generator = Generator::new();
    assert_eq!(
        generator.set_fixed_input_size(Generator::MAX_INPUT_SIZE + 1),
        Err(GeneratorError::FixedSizeTooLarge)
    );
}

#[test]
fn test_generator_length_mismatch() {
    let mut generator = Generator::new();
    let buf = "Hello, World!".as_bytes();

    // Use update
    // Intentionally give a wrong size (this operation itself should succeed).
    assert_eq!(generator.set_fixed_input_size_in_usize(buf.len() - 1), Ok(()));
    generator.update(buf);
    assert_eq!(generator.input_size(), buf.len() as u64);
    assert!(generator.may_warn_about_small_input_size());
    // Error occurs when finalization.
    assert_eq!(generator.finalize(), Err(GeneratorError::FixedSizeMismatch));
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        assert_eq!(generator.finalize_raw::<$trunc, $bs1, $bs2>(), Err(GeneratorError::FixedSizeMismatch));
    }}
    test_for_each_generator_finalization!(test);

    // Use update (and use the correct size)
    generator.reset();
    assert_eq!(generator.set_fixed_input_size_in_usize(buf.len()), Ok(()));
    generator.update(buf);
    assert_eq!(generator.input_size(), buf.len() as u64);
    assert!(generator.may_warn_about_small_input_size());
    // No errors occur on finalization.
    assert!(generator.finalize().is_ok());

    // Use update_by_iter
    // Intentionally give a wrong size (this operation itself should succeed).
    generator.reset();
    assert_eq!(generator.set_fixed_input_size_in_usize(buf.len() - 1), Ok(()));
    generator.update_by_iter(buf.iter().cloned());
    assert_eq!(generator.input_size(), buf.len() as u64);
    assert!(generator.may_warn_about_small_input_size());
    // Error occurs when finalization.
    assert_eq!(generator.finalize(), Err(GeneratorError::FixedSizeMismatch));
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        assert_eq!(generator.finalize_raw::<$trunc, $bs1, $bs2>(), Err(GeneratorError::FixedSizeMismatch));
    }}
    test_for_each_generator_finalization!(test);

    // Use update_by_iter (and use the correct size)
    generator.reset();
    assert_eq!(generator.set_fixed_input_size_in_usize(buf.len()), Ok(()));
    generator.update_by_iter(buf.iter().cloned());
    assert_eq!(generator.input_size(), buf.len() as u64);
    assert!(generator.may_warn_about_small_input_size());
    // Error occurs when finalization.
    assert!(generator.finalize().is_ok());
}

#[cfg(feature = "tests-very-slow")]
#[test]
fn test_generator_large_trigger_last_hash() {
    /*
        This test triggers "last hash" (FNV-based) output on the generator.

        Input size:
        96GiB + 1B

        SHA-256 of the generator input:
        2b8b92765a232967d96a9d23a869620ceb7ee316270bc4b566a23995d95630a2

        Equivalent Zstandard-compressed file is available at:
        `ffuzzy/data/testsuite/generate/large_trigger_last_hash.bin.zstd`
        (excluded from the package but in the source repository).

        Be careful!  This Zstandard-compressed file is a zip bomb!
    */
    const ZERO_1M: [u8; 1048576] = [0; 1048576];
    let mut generator = Generator::new();
    generator.set_fixed_input_size(96 * 1024 * 1048576 + 1).unwrap();
    for _ in 0..64 {
        generator.update(b"`]]]_CT");
    }
    generator.update(&ZERO_1M[0..1048128]);
    // Now: 1MiB (7 * 64 + 1048128 == 1048576)
    // Feed zero bytes until it reaches 96GiB (98304MiB).
    // The loop variable is processed MiBs **after** feeding data to the generator.
    for _mb_processed in 2..=(96 * 1024) {
        generator.update(&ZERO_1M[..]);
        #[cfg(feature = "std")]
        if _mb_processed % 1024 == 0 {
            println!("{:2}GiB of 96GiB processed...", _mb_processed / 1024);
        }
    }
    // Append 1 byte (96GiB + 1 in total) to trigger h_last output.
    generator.update(&[1]);
    assert!(!generator.may_warn_about_small_input_size());
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        type FuzzyHashType = FuzzyHashData<$bs1, $bs2, false>;
        let hash_expected = FuzzyHashType::from_str(
            "3221225472:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiH:k"
        ).unwrap();
        assert_eq!(
            hash_expected, generator.finalize_raw::<$trunc, $bs1, $bs2>().unwrap()
        );
    }}
    test_for_each_generator_finalization!(test);
}

#[cfg(feature = "tests-very-slow")]
#[test]
fn test_generator_large_trigger_last_hash_by_iter() {
    const ZERO_1M: [u8; 1048576] = [0; 1048576];
    let mut generator = Generator::new();
    generator.set_fixed_input_size(96 * 1024 * 1048576 + 1).unwrap();
    for _ in 0..64 {
        generator.update_by_iter(b"`]]]_CT".iter().cloned());
    }
    generator.update_by_iter(ZERO_1M[0..1048128].iter().cloned());
    // Now: 1MiB (7 * 64 + 1048128 == 1048576)
    // Feed zero bytes until it reaches 96GiB (98304MiB).
    // The loop variable is processed MiBs **after** feeding data to the generator.
    for _mb_processed in 2..=(96 * 1024) {
        generator.update_by_iter(ZERO_1M[..].iter().cloned());
        #[cfg(feature = "std")]
        if _mb_processed % 1024 == 0 {
            println!("{:2}GiB of 96GiB processed...", _mb_processed / 1024);
        }
    }
    // Append 1 byte (96GiB + 1 in total) to trigger h_last output.
    generator.update_by_iter([1; 1][..].iter().cloned());
    assert!(!generator.may_warn_about_small_input_size());
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        type FuzzyHashType = FuzzyHashData<$bs1, $bs2, false>;
        let hash_expected = FuzzyHashType::from_str(
            "3221225472:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiH:k"
        ).unwrap();
        assert_eq!(
            hash_expected, generator.finalize_raw::<$trunc, $bs1, $bs2>().unwrap()
        );
    }}
    test_for_each_generator_finalization!(test);
}

#[cfg(feature = "tests-very-slow")]
#[test]
fn test_generator_large_trigger_last_hash_by_byte() {
    const ZERO_1M: [u8; 1048576] = [0; 1048576];
    let mut generator = Generator::new();
    generator.set_fixed_input_size(96 * 1024 * 1048576 + 1).unwrap();
    for _ in 0..64 {
        for &ch in b"`]]]_CT".iter() {
            generator.update_by_byte(ch);
        }
    }
    for &ch in ZERO_1M[0..1048128].iter() {
        generator.update_by_byte(ch);
    }
    // Now: 1MiB (7 * 64 + 1048128 == 1048576)
    // Feed zero bytes until it reaches 96GiB (98304MiB).
    // The loop variable is processed MiBs **after** feeding data to the generator.
    for _mb_processed in 2..=(96 * 1024) {
        for &ch in ZERO_1M[..].iter() {
            generator.update_by_byte(ch);
        }
        #[cfg(feature = "std")]
        if _mb_processed % 1024 == 0 {
            println!("{:2}GiB of 96GiB processed...", _mb_processed / 1024);
        }
    }
    // Append 1 byte (96GiB + 1 in total) to trigger h_last output.
    generator.update_by_byte(1);
    assert!(!generator.may_warn_about_small_input_size());
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        type FuzzyHashType = FuzzyHashData<$bs1, $bs2, false>;
        let hash_expected = FuzzyHashType::from_str(
            "3221225472:iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiH:k"
        ).unwrap();
        assert_eq!(
            hash_expected, generator.finalize_raw::<$trunc, $bs1, $bs2>().unwrap()
        );
    }}
    test_for_each_generator_finalization!(test);
}

#[cfg(feature = "tests-very-slow")]
#[test]
fn test_generator_large_error() {
    /*
        This test triggers "input too large error".

        Input size:
        192GiB + 1B

        SHA-256 of the generator input:
        e613117320077150ddb32b33c2e8aaeaa63e9590a656c5aba04a91fa47d1c1b5
    */
    const ZERO_1M: [u8; 1048576] = [0; 1048576];
    let mut generator = Generator::new();
    // The loop variable is processed MiBs **after** feeding data to the generator.
    for _mb_processed in 1..=(192 * 1024) {
        generator.update(&ZERO_1M[..]);
        #[cfg(feature = "std")]
        if _mb_processed % 1024 == 0 {
            println!("{:3}GiB of 192GiB processed...", _mb_processed / 1024);
        }
    }
    // Append 1 byte (192GiB + 1 in total) to trigger the "input too large" error.
    generator.update(&[0]);
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        assert_eq!(generator.finalize_raw::<$trunc, $bs1, $bs2>(), Err(GeneratorError::InputSizeTooLarge));
    }}
    test_for_each_generator_finalization!(test);
}

#[cfg(feature = "tests-very-slow")]
#[test]
fn test_generator_large_error_by_iter() {
    const ZERO_1M: [u8; 1048576] = [0; 1048576];
    let mut generator = Generator::new();
    // The loop variable is processed MiBs **after** feeding data to the generator.
    for _mb_processed in 1..=(192 * 1024) {
        generator.update_by_iter(ZERO_1M[..].iter().cloned());
        #[cfg(feature = "std")]
        if _mb_processed % 1024 == 0 {
            println!("{:3}GiB of 192GiB processed...", _mb_processed / 1024);
        }
    }
    // Append 1 byte (192GiB + 1 in total) to trigger the "input too large" error.
    generator.update_by_iter([0u8; 1][..].iter().cloned());
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        assert_eq!(generator.finalize_raw::<$trunc, $bs1, $bs2>(), Err(GeneratorError::InputSizeTooLarge));
    }}
    test_for_each_generator_finalization!(test);
}

#[cfg(feature = "tests-very-slow")]
#[test]
fn test_generator_large_error_by_byte() {
    const ZERO_1M: [u8; 1048576] = [0; 1048576];
    let mut generator = Generator::new();
    // The loop variable is processed MiBs **after** feeding data to the generator.
    for _mb_processed in 1..=(192 * 1024) {
        for &ch in ZERO_1M[..].iter() {
            generator.update_by_byte(ch);
        }
        #[cfg(feature = "std")]
        if _mb_processed % 1024 == 0 {
            println!("{:3}GiB of 192GiB processed...", _mb_processed / 1024);
        }
    }
    // Append 1 byte (192GiB + 1 in total) to trigger the "input too large" error.
    generator.update_by_byte(0);
    macro_rules! test {($trunc: expr, $bs1: expr, $bs2: expr) => {
        assert_eq!(generator.finalize_raw::<$trunc, $bs1, $bs2>(), Err(GeneratorError::InputSizeTooLarge));
    }}
    test_for_each_generator_finalization!(test);
}

#[cfg(feature = "std")]
#[test]
fn test_generator_small_precomputed_vectors() {
    use std::io::{BufRead, BufReader, Read};
    use std::fs::File;
    use std::str::FromStr;
    use crate::hash::LongRawFuzzyHash;

    let index = BufReader::new(
        File::open("data/testsuite/generate-small.ssdeep.txt").unwrap()
    );
    let mut generator = Generator::new();
    for index_ln in index.lines() {
        /*
            Read a line from the index file.
        */
        let index_ln = index_ln.unwrap();
        if index_ln.len() == 0 || index_ln.chars().next() == Some('#') {
            continue;
        }
        let tokens: Vec<&str> = index_ln.split_whitespace().collect();
        assert!(tokens.len() == 3);
        // $1: filename
        let filename = tokens[0];
        // $2: flags (truncated or non-truncated, or check both)
        const TEST_TRUNC_1: u8 = 1;
        const TEST_TRUNC_0: u8 = 2;
        const TEST_ELIMSEQ: u8 = 4; // Do the normalization.
        const TEST_WASLONG: u8 = 8; // Long fuzzy hash before normalization.
        let flags = u8::from_str_radix(tokens[1], 10).unwrap();
        // $3: expected fuzzy hash
        let fuzzy_str = tokens[2];
        let fuzzy_expected = LongRawFuzzyHash::from_str(fuzzy_str).unwrap();
        /*
            Read the corresponding file.
        */
        let mut contents = Vec::<u8>::new();
        File::open(filename).unwrap().read_to_end(&mut contents).unwrap();
        /*
            Test fuzzy hash generator as follows:
        */
        println!("Testing: {}...", filename);
        // Note:
        // Some explicit type annotation (including following two lines) is
        // to make sure that the result of finalize_raw method matches the
        // expected type,
        if (flags & TEST_TRUNC_1) != 0 {
            /*
                Test the generator with truncation.
            */
            let mut fuzzy_expected_trunc: RawFuzzyHash = RawFuzzyHash::new();
            fuzzy_expected.try_into_mut_short(&mut fuzzy_expected_trunc).unwrap();
            // Test three ways to generate fuzzy hashes
            {
                fn check_results(
                    generator: &Generator,
                    flags: u8,
                    fuzzy_str: &str,
                    fuzzy_expected: &LongRawFuzzyHash,
                    fuzzy_expected_trunc: &RawFuzzyHash
                ) {
                    let mut fuzzy_generated: LongRawFuzzyHash = generator
                        .finalize_raw::<true, {BlockHash::FULL_SIZE}, {BlockHash::FULL_SIZE}>()
                        .unwrap();
                    let mut fuzzy_generated_trunc: RawFuzzyHash = generator
                        .finalize_raw::<true, {BlockHash::FULL_SIZE}, {BlockHash::HALF_SIZE}>()
                        .unwrap();
                    if (flags & TEST_ELIMSEQ) != 0 {
                        fuzzy_generated.normalize_in_place();
                        fuzzy_generated_trunc.normalize_in_place();
                    }
                    assert_eq!(*fuzzy_expected,       fuzzy_generated);
                    assert_eq!(*fuzzy_expected_trunc, fuzzy_generated_trunc);
                    assert_eq!(fuzzy_str, fuzzy_generated.to_string());
                    assert_eq!(fuzzy_str, fuzzy_generated_trunc.to_string());
                }
                generator.reset();
                generator.update(contents.as_slice());
                check_results(&generator, flags, &fuzzy_str, &fuzzy_expected, &fuzzy_expected_trunc);
                generator.reset();
                generator.update_by_iter(contents.iter().cloned());
                check_results(&generator, flags, &fuzzy_str, &fuzzy_expected, &fuzzy_expected_trunc);
                generator.reset();
                for &b in contents.iter() {
                    generator.update_by_byte(b);
                }
                check_results(&generator, flags, &fuzzy_str, &fuzzy_expected, &fuzzy_expected_trunc);
            }
        }
        if (flags & TEST_TRUNC_0) != 0 {
            /*
                Test the generator without truncation.
            */
            let is_long = fuzzy_expected.block_hash_2().len() > BlockHash::HALF_SIZE;
            let mut fuzzy_expected_trunc: RawFuzzyHash = RawFuzzyHash::new();
            match fuzzy_expected.try_into_mut_short(&mut fuzzy_expected_trunc) {
                Ok(_)  => assert!(!is_long),
                Err(_) => assert!(is_long),  // Consider truncation error.
            }
            // Test three ways to generate fuzzy hashes
            {
                fn check_results(
                    generator: &Generator,
                    flags: u8,
                    is_long: bool,
                    fuzzy_str: &str,
                    fuzzy_expected: &LongRawFuzzyHash,
                    fuzzy_expected_trunc: &RawFuzzyHash
                ) {
                    let mut fuzzy_generated: LongRawFuzzyHash = generator
                        .finalize_without_truncation() // <false, FULL_SIZE, FULL_SIZE>
                        .unwrap();
                    let mut fuzzy_generated_trunc: RawFuzzyHash = match generator
                        .finalize_raw::<false, {BlockHash::FULL_SIZE}, {BlockHash::HALF_SIZE}>() {
                            Ok(h) => {
                                assert!(!is_long);
                                h
                            },
                            Err(_) => {
                                // Consider truncation error.
                                assert!(is_long || (flags & TEST_WASLONG) != 0);
                                if is_long {
                                    RawFuzzyHash::new()
                                }
                                else {
                                    RawFuzzyHash::try_from(fuzzy_generated.clone_normalized()).unwrap()
                                }
                            }
                        };
                    if (flags & TEST_ELIMSEQ) != 0 {
                        fuzzy_generated.normalize_in_place();
                        fuzzy_generated_trunc.normalize_in_place();
                    }
                    assert_eq!(*fuzzy_expected,       fuzzy_generated);
                    assert_eq!(*fuzzy_expected_trunc, fuzzy_generated_trunc);
                    assert_eq!(fuzzy_str, fuzzy_generated.to_string());
                    if !is_long {
                        assert_eq!(fuzzy_str, fuzzy_generated_trunc.to_string());
                    }
                }
                generator.reset();
                generator.update(contents.as_slice());
                check_results(&generator, flags, is_long, &fuzzy_str, &fuzzy_expected, &fuzzy_expected_trunc);
                generator.reset();
                generator.update_by_iter(contents.iter().cloned());
                check_results(&generator, flags, is_long, &fuzzy_str, &fuzzy_expected, &fuzzy_expected_trunc);
                generator.reset();
                for &b in contents.iter() {
                    generator.update_by_byte(b);
                }
                check_results(&generator, flags, is_long, &fuzzy_str, &fuzzy_expected, &fuzzy_expected_trunc);
            }
        }
    }
}
