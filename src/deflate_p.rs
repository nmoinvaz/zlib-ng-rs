//! deflate_p.h -- Private inline functions and macros shared with more than
//!                one deflate method
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_int;
use core::ptr;

use crate::deflate::{deflate_state, flush_pending};
use crate::trees::zng_tr_flush_block;
#[cfg(not(feature = "lit-mem"))]
use crate::zbuild::OPTIMAL_CMP;
#[cfg(not(feature = "lit-mem"))]
use crate::zmemory::zng_memwrite_4;

/* ===========================================================================
 * Save the match info and tally the frequency counts. Return true if
 * the current block must be flushed.
 */

/// # Safety
///
/// `s` must point to a deflate_state whose symbol buffer has room for another symbol.
#[inline(always)]
pub(crate) unsafe fn zng_tr_tally_lit(s: *mut deflate_state, c: u8) -> bool {
    /* c is the unmatched char */
    // SAFETY: the caller guarantees the state is valid and the symbol buffer has room.
    unsafe {
        let sym_next = (*s).sym_next;
        #[cfg(feature = "lit-mem")]
        {
            *(*s).d_buf.add(sym_next as usize) = 0;
            *(*s).l_buf.add(sym_next as usize) = c;
            (*s).sym_next = sym_next + 1;
        }
        #[cfg(not(feature = "lit-mem"))]
        {
            let sym = (*s).sym_buf.add(sym_next as usize);
            if OPTIMAL_CMP >= 32 {
                zng_memwrite_4(sym, (u32::from(c) << 16).to_le());
            } else {
                *sym = 0;
                *sym.add(1) = 0;
                *sym.add(2) = c;
            }
            (*s).sym_next = sym_next + 3;
        }
        (*s).dyn_ltree[usize::from(c)].fc += 1;
        (*s).sym_next == (*s).sym_end
    }
}

/* ===========================================================================
 * Flush the current block, with given end-of-file flag.
 * IN assertion: strstart is set to the end of the current match.
 */
/// # Safety
///
/// `s` must point to a deflate_state and `window` must be its window.
#[inline(always)]
pub(crate) unsafe fn flush_block_only(s: *mut deflate_state, window: *mut u8, last: bool) {
    // SAFETY: the caller guarantees the state and its window are valid.
    unsafe {
        let block_start = (*s).block_start;
        zng_tr_flush_block(
            s,
            if block_start >= 0 {
                window.add(block_start as usize)
            } else {
                ptr::null_mut()
            },
            ((*s).strstart as i32).wrapping_sub(block_start) as u32,
            c_int::from(last),
        );
        (*s).block_start = (*s).strstart as i32;
        flush_pending((*s).strm);
    }
}

/// Same but force premature exit if necessary.
macro_rules! flush_block {
    ($s:expr, $window:expr, $last:expr) => {
        $crate::deflate_p::flush_block_only($s, $window, $last);
        if (*(*$s).strm).avail_out == 0 {
            return if $last {
                $crate::deflate::block_state::finish_started
            } else {
                $crate::deflate::block_state::need_more
            };
        }
    };
}
pub(crate) use flush_block;
