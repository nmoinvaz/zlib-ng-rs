//! Port of the parts of fallback_builtins.h that the Rust sources need.

/* Byte-position of the first differing byte in a native-endian XOR diff,
 * using CTZ on little-endian and CLZ on big-endian to avoid a byte-swap. */
#[inline(always)]
pub(crate) fn zng_first_diff_byte64(diff: u64) -> u32 {
    if cfg!(target_endian = "big") {
        diff.leading_zeros() / 8
    } else {
        diff.trailing_zeros() / 8
    }
}

/* Builds a mask of the first n bytes (1..8) so an XOR diff can be tested for
 * a leading n-byte match with a single AND. */
#[inline(always)]
pub(crate) fn zng_first_bytes_mask64(n: u32) -> u64 {
    if cfg!(target_endian = "big") {
        u64::MAX << ((8 - n) * 8)
    } else {
        u64::MAX >> ((8 - n) * 8)
    }
}
