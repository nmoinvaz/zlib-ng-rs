//! Declarations for the parts of trees.h and trees.c that are still built from C.

use core::ffi::c_int;

use crate::deflate::deflate_state;
use crate::zutil::{STD_MAX_MATCH, STD_MIN_MATCH};

/// see definition of array dist_code in trees.c
pub(crate) const DIST_CODE_LEN: usize = 512;

unsafe extern "C" {
    pub(crate) fn zng_tr_flush_block(
        s: *mut deflate_state,
        buf: *mut u8,
        stored_len: u32,
        last: c_int,
    );

    /// Distance codes. The first 256 values correspond to the distances 3 .. 258, the last 256
    /// values correspond to the top 8 bits of the 15 bit distances.
    pub(crate) safe static zng_dist_code: [u8; DIST_CODE_LEN];
    /// length code for each normalized match length (0 == STD_MIN_MATCH)
    pub(crate) safe static zng_length_code: [u8; STD_MAX_MATCH - STD_MIN_MATCH + 1];
}

/// Mapping from a distance to a distance code. dist is the distance - 1 and must be lower than
/// 32768.
///
/// # Safety
///
/// `dist` must be below 32768.
#[inline(always)]
pub(crate) unsafe fn d_code(dist: u32) -> u8 {
    if dist < 256 {
        zng_dist_code[dist as usize]
    } else {
        // SAFETY: the caller guarantees dist is below 32768, so the index is below DIST_CODE_LEN.
        unsafe { *zng_dist_code.get_unchecked(256 + (dist >> 7) as usize) }
    }
}
