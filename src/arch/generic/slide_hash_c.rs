//! slide_hash.c -- slide hash table C implementation
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::slice;

use crate::deflate::{HASH_SIZE, Pos, deflate_state};

/* ===========================================================================
 * Slide the hash table when sliding the window down
 */
#[inline(always)]
fn slide_hash_c_chain(table: &mut [Pos], wsize: Pos) {
    for entry in table {
        *entry = entry.saturating_sub(wsize);
    }
    /* If entries is not on any hash chain, prev[entries] is garbage but
     * its value will never be used.
     */
}

/// # Safety
///
/// `s` must point to a deflate_state whose head table holds HASH_SIZE entries and whose prev table
/// holds w_size entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slide_hash_c(s: *mut deflate_state) {
    // SAFETY: the caller guarantees s and both of its tables are valid.
    unsafe {
        let wsize = (*s).w_size as Pos;

        slide_hash_c_chain(slice::from_raw_parts_mut((*s).head, HASH_SIZE), wsize);
        slide_hash_c_chain(
            slice::from_raw_parts_mut((*s).prev, usize::from(wsize)),
            wsize,
        );
    }
}

/// # Safety
///
/// `s` must point to a deflate_state whose head table holds HASH_SIZE entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slide_hash_head_c(s: *mut deflate_state) {
    // SAFETY: the caller guarantees s and its head table are valid.
    unsafe {
        let wsize = (*s).w_size as Pos;

        slide_hash_c_chain(slice::from_raw_parts_mut((*s).head, HASH_SIZE), wsize);
    }
}
