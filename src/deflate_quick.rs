//! The deflate_quick deflate strategy, designed to be used when cycles are
//! at a premium.
//!
//! Copyright (C) 2013 Intel Corporation. All rights reserved.
//! Authors:
//!  Wajdi Feghali   <wajdi.k.feghali@intel.com>
//!  Jim Guilford    <james.guilford@intel.com>
//!  Vinodh Gopal    <vinodh.gopal@intel.com>
//!     Erdinc Ozturk   <erdinc.ozturk@intel.com>
//!  Jim Kukunas     <james.t.kukunas@linux.intel.com>
//!
//! Portions are Copyright (C) 2016 12Sided Technology, LLC.
//! Author:
//!  Phil Vachon     <pvachon@12sidedtech.com>
//!
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_int;

use crate::deflate::{
    BIT_BUF_SIZE, MIN_LOOKAHEAD, block_state, deflate_state, fill_window, flush_pending, max_dist,
};
use crate::deflate_p::check_match;
use crate::functable;
use crate::insert_string_p::insert_knuth_val_head;
use crate::trees::{static_dtree, static_ltree};
use crate::trees_emit::{
    zng_tr_emit_dist, zng_tr_emit_end_block, zng_tr_emit_lit, zng_tr_emit_tree,
};
use crate::zbuild::{likely, unlikely};
use crate::zlib::{Z_FINISH, Z_NO_FLUSH};
use crate::zmemory::zng_memread_4;
use crate::zutil::{STATIC_TREES, STD_MAX_MATCH, STD_MIN_MATCH, WANT_MIN_MATCH};

const MIN_MATCH: u32 = STD_MIN_MATCH as u32;
const WANT_MATCH: u32 = WANT_MIN_MATCH as u32;

/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 8 more bytes.
#[inline(always)]
unsafe fn quick_start_block(s: *mut deflate_state, strstart: u32, last: bool) {
    // SAFETY: the caller guarantees the state is valid and the pending buffer has room.
    unsafe {
        zng_tr_emit_tree(s, STATIC_TREES, c_int::from(last));
        (*s).block_open = 1 + u32::from(last);
        (*s).block_start = strstart as i32;
    }
}

/// # Safety
///
/// `s` must point to a deflate_state with a valid stream behind it, whose pending buffer has room
/// for 16 more bytes.
#[inline(always)]
unsafe fn quick_end_block(s: *mut deflate_state, strstart: u32, last: bool) -> bool {
    // SAFETY: the caller guarantees the state and its stream are valid and the pending buffer
    // has room.
    unsafe {
        if (*s).block_open != 0 {
            zng_tr_emit_end_block(s, static_ltree.as_ptr(), c_int::from(last));
            (*s).block_open = 0;
            (*s).block_start = strstart as i32;
            flush_pending((*s).strm);
            return (*(*s).strm).avail_out == 0;
        }
        false
    }
}

/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deflate_quick(s: *mut deflate_state, flush: c_int) -> block_state {
    // SAFETY: the caller guarantees the state is valid. fill_window keeps MIN_LOOKAHEAD bytes
    // available at strstart except at the end of the input, and the check at the top of the loop
    // keeps room in the pending buffer for the bits of one more symbol.
    unsafe {
        let mut strstart = (*s).strstart;
        let mut lookahead = (*s).lookahead;
        let last = flush == Z_FINISH;

        if unlikely(last && (*s).block_open != 2) {
            /* Emit end of previous block */
            if quick_end_block(s, strstart, false) {
                return block_state::need_more;
            }
            /* Emit start of last block */
            quick_start_block(s, strstart, last);
        } else if unlikely((*s).block_open == 0 && lookahead > 0) {
            /* Start new block only when we have lookahead data, so that if no
            input data is given an empty block will not be written */
            quick_start_block(s, strstart, last);
        }

        let window = (*s).window;

        loop {
            if unlikely((*s).pending + ((BIT_BUF_SIZE + 7) >> 3) >= (*s).pending_buf_size) {
                flush_pending((*s).strm);
                if (*(*s).strm).avail_out == 0 {
                    (*s).lookahead = lookahead;
                    (*s).strstart = strstart;
                    return if last
                        && (*(*s).strm).avail_in == 0
                        && (*s).bi_valid == 0
                        && (*s).block_open == 0
                    {
                        block_state::finish_started
                    } else {
                        block_state::need_more
                    };
                }
            }

            if unlikely(lookahead < MIN_LOOKAHEAD) {
                (*s).lookahead = lookahead;
                (*s).strstart = strstart;
                fill_window(s);
                lookahead = (*s).lookahead;
                strstart = (*s).strstart;
                if unlikely(lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH) {
                    return block_state::need_more;
                }
                if unlikely(lookahead == 0) {
                    break;
                }

                if unlikely((*s).block_open == 0) {
                    /* Start new block when we have lookahead data, so that if no
                    input data is given an empty block will not be written */
                    quick_start_block(s, strstart, last);
                }
            }

            let str_val = u32::from_le(zng_memread_4(window.add(strstart as usize)));

            if likely(lookahead >= WANT_MATCH) {
                let hash_head = insert_knuth_val_head(s, strstart, str_val);
                let dist = i64::from(strstart) - i64::from(hash_head);

                if dist <= i64::from(max_dist(s)) && dist > 0 {
                    let match_start = window.add(hash_head as usize);
                    let match_val = u32::from_le(zng_memread_4(match_start));

                    if str_val == match_val {
                        let scan_start = window.add(strstart as usize);
                        let mut match_len =
                            functable::compare256(scan_start.add(2), match_start.add(2)) + 2;

                        if match_len >= WANT_MATCH {
                            if unlikely(match_len > lookahead) {
                                match_len = lookahead;
                            }

                            debug_assert!(match_len <= STD_MAX_MATCH as u32, "match too long");
                            debug_assert!(
                                strstart <= u32::from(u16::MAX),
                                "strstart should fit in uint16_t"
                            );
                            check_match(s, strstart, hash_head, match_len);

                            zng_tr_emit_dist(
                                s,
                                static_ltree.as_ptr(),
                                static_dtree.as_ptr(),
                                match_len - MIN_MATCH,
                                dist as u32,
                            );
                            lookahead -= match_len;
                            strstart += match_len;
                            continue;
                        }
                    }
                }
            }

            zng_tr_emit_lit(s, static_ltree.as_ptr(), u32::from(str_val as u8));
            strstart += 1;
            lookahead -= 1;
        }

        (*s).lookahead = lookahead;
        (*s).strstart = strstart;
        (*s).insert = if strstart < MIN_MATCH - 1 {
            strstart
        } else {
            MIN_MATCH - 1
        };
        if unlikely(last) {
            if quick_end_block(s, strstart, true) {
                return block_state::finish_started;
            }
            return block_state::finish_done;
        }

        if quick_end_block(s, strstart, false) {
            return block_state::need_more;
        }
        block_state::block_done
    }
}
