//! deflate_p.h -- Private inline functions and macros shared with more than
//!                one deflate method
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_int;
use core::ptr;

#[cfg(feature = "s390-dfltcc-deflate")]
use crate::arch::s390::dfltcc_deflate::deflate_need_checksum;
use crate::deflate::{D_CODES, LITERALS, deflate_state, flush_pending, max_dist};
use crate::functable;
use crate::trees::{d_code, zng_length_code, zng_tr_flush_block};
#[cfg(not(feature = "lit-mem"))]
use crate::zbuild::OPTIMAL_CMP;
use crate::zbuild::{z_checksum_t, z_uintmax_t};
use crate::zlib::z_stream;
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

/// # Safety
///
/// `s` must point to a deflate_state whose symbol buffer has room for another symbol, and `dist`
/// must be a match distance within its window.
#[inline(always)]
pub(crate) unsafe fn zng_tr_tally_dist(s: *mut deflate_state, mut dist: u32, len: u32) -> bool {
    /* dist: distance of matched string */
    /* len: match length-STD_MIN_MATCH */
    // SAFETY: the caller guarantees the state is valid and the symbol buffer has room. A valid
    // distance is below MAX_DIST, so its code is below D_CODES.
    unsafe {
        let sym_next = (*s).sym_next;
        #[cfg(feature = "lit-mem")]
        {
            debug_assert!(dist <= u32::from(u16::MAX), "dist should fit in uint16_t");
            debug_assert!(len <= u32::from(u8::MAX), "len should fit in uint8_t");
            *(*s).d_buf.add(sym_next as usize) = dist as u16;
            *(*s).l_buf.add(sym_next as usize) = len as u8;
            (*s).sym_next = sym_next + 1;
        }
        #[cfg(not(feature = "lit-mem"))]
        {
            let sym = (*s).sym_buf.add(sym_next as usize);
            if OPTIMAL_CMP >= 32 {
                zng_memwrite_4(sym, (dist | (len << 16)).to_le());
            } else {
                *sym = dist as u8;
                *sym.add(1) = (dist >> 8) as u8;
                *sym.add(2) = len as u8;
            }
            (*s).sym_next = sym_next + 3;
        }
        dist -= 1;
        debug_assert!(
            dist < max_dist(s) && usize::from(d_code(dist)) < D_CODES,
            "zng_tr_tally: bad match"
        );

        (*s).dyn_ltree[usize::from(zng_length_code[usize::from(len as u8)]) + LITERALS + 1].fc += 1;
        (*s).dyn_dtree
            .get_unchecked_mut(usize::from(d_code(dist)))
            .fc += 1;
        (*s).sym_next == (*s).sym_end
    }
}

/* ===========================================================================
 * Check that the match at match_start is indeed a match.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose window holds `length` bytes at `start` and `match_pos`.
#[cfg(debug_assertions)]
pub(crate) unsafe fn check_match(s: *mut deflate_state, start: u32, match_pos: u32, length: u32) {
    use crate::zutil::{STD_MAX_MATCH, STD_MIN_MATCH};

    /* check that the match length is valid*/
    assert!(
        length as usize >= STD_MIN_MATCH && length as usize <= STD_MAX_MATCH,
        "invalid match length: start {start}, match {match_pos}, length {length}"
    );
    /* check that the match isn't at the same position as the start string */
    assert!(
        match_pos != start,
        "invalid match position: start {start}, match {match_pos}, length {length}"
    );
    /* check that the match is indeed a match */
    // SAFETY: the caller guarantees both ranges lie inside the window.
    let (matched, scanned) = unsafe {
        let window = (*s).window;
        (
            core::slice::from_raw_parts(window.add(match_pos as usize), length as usize),
            core::slice::from_raw_parts(window.add(start as usize), length as usize),
        )
    };
    assert!(
        matched == scanned,
        "invalid match: start {start}, match {match_pos}, length {length}"
    );
}

/// Checks nothing in release builds, like the C macro without ZLIB_DEBUG.
#[cfg(not(debug_assertions))]
#[inline(always)]
pub(crate) unsafe fn check_match(
    _s: *mut deflate_state,
    _start: u32,
    _match_pos: u32,
    _length: u32,
) {
}

/// Whether deflate computes the check value itself, which hardware deflate on s390 takes over.
#[cfg(not(feature = "s390-dfltcc-deflate"))]
#[inline(always)]
unsafe fn deflate_need_checksum(_strm: *mut z_stream) -> bool {
    true
}

/* ===========================================================================
 * Read a new buffer from the current input stream, update the adler32 and total number of
 * bytes read.  All deflate() input goes through this function so some applications may wish
 * to modify it to avoid allocating a large strm->next_in buffer and copying from it.
 * See also flush_pending_inline().
 */
/// # Safety
///
/// `strm` must be a valid deflate stream and `buf` must be valid for writes of `size` bytes.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
#[inline(always)]
pub(crate) unsafe fn read_buf(strm: *mut z_stream, buf: *mut u8, size: u32) -> u32 {
    // SAFETY: the caller guarantees the stream and the buffer are valid. next_in holds avail_in
    // bytes, and len is no more than that.
    unsafe {
        let s = (*strm).state.cast::<deflate_state>();
        let len = (*strm).avail_in.min(size);

        if len == 0 {
            return 0;
        }

        if !deflate_need_checksum(strm) {
            ptr::copy_nonoverlapping((*strm).next_in, buf, len as usize);
        } else if (*s).wrap == 2 {
            (*strm).adler = z_checksum_t::from(functable::crc32_copy(
                (*strm).adler as u32,
                buf,
                (*strm).next_in,
                len as usize,
            ));
        } else if (*s).wrap == 1 {
            (*strm).adler = z_checksum_t::from(functable::adler32_copy(
                (*strm).adler as u32,
                buf,
                (*strm).next_in,
                len as usize,
            ));
        } else {
            ptr::copy_nonoverlapping((*strm).next_in, buf, len as usize);
        }

        (*strm).avail_in -= len;
        (*strm).next_in = (*strm).next_in.add(len as usize);
        (*strm).total_in = (*strm).total_in.wrapping_add(len as z_uintmax_t);
        len
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

/// Maximum stored block length in deflate format (not including header).
pub(crate) const MAX_STORED: u32 = 65535;
