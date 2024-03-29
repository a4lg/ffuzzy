use crate::hash::block::block_hash;

const OLD_HASH_INIT: u32 = 0x28021967;
pub(super) const FNV_HASH_INIT: u8 = (OLD_HASH_INIT % block_hash::ALPHABET_SIZE as u32) as u8;
pub(super) const FNV_HASH_PRIME: u32 = 0x01000193;

#[cfg(not(feature = "opt-reduce-fnv-table"))]
pub(super) const FNV_TABLE: [[u8; block_hash::ALPHABET_SIZE]; block_hash::ALPHABET_SIZE] = {
    let mut array = [[0u8; block_hash::ALPHABET_SIZE]; block_hash::ALPHABET_SIZE];
    let mut state = 0u8;
    while state < 64 {
        let mut ch = 0u8;
        while ch < 64 {
            array[state as usize][ch as usize] =
                (((state as u32).wrapping_mul(FNV_HASH_PRIME) as u8) ^ ch)
                    % block_hash::ALPHABET_SIZE as u8;
            ch += 1;
        }
        state += 1;
    }
    array
};
