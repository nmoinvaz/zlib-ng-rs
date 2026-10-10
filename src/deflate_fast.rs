//! deflate_fast.c -- compress data using the fast strategy of deflation algorithm
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_int;

use crate::deflate::{MIN_LOOKAHEAD, block_state, deflate_state, fill_window, max_dist};
use crate::deflate_p::{check_match, flush_block, zng_tr_tally_dist, zng_tr_tally_lit};
use crate::functable;
use crate::insert_string_p::{insert_knuth, insert_knuth_batch_static, insert_knuth_val};
use crate::zbuild::{likely, unlikely};
use crate::zlib::{Z_FINISH, Z_NO_FLUSH};
use crate::zmemory::zng_memread_4;
use crate::zutil::{STD_MIN_MATCH, WANT_MIN_MATCH};

/* ===========================================================================
 * Compress as much as possible from the input stream, return the current
 * block state.
 * This function does not perform lazy evaluation of matches and inserts
 * new strings in the dictionary only for unmatched strings or for short
 * matches. It is used only for the fast compression options.
 */
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deflate_fast(s: *mut deflate_state, flush: c_int) -> block_state {
    const MIN_MATCH: u32 = STD_MIN_MATCH as u32;
    const WANT_MATCH: u32 = WANT_MIN_MATCH as u32;

    // SAFETY: the caller guarantees the state is valid. fill_window keeps MIN_LOOKAHEAD bytes
    // available at strstart except at the end of the input.
    unsafe {
        let window = (*s).window;
        let mut match_len = 0;

        loop {
            let lc;

            /* Make sure that we always have enough lookahead, except
             * at the end of the input file. We need STD_MAX_MATCH bytes
             * for the next match, plus WANT_MIN_MATCH bytes to insert the
             * string following the next match.
             */
            let mut lookahead = (*s).lookahead;
            if unlikely(lookahead < MIN_LOOKAHEAD) {
                fill_window(s);
                lookahead = (*s).lookahead;
                if unlikely(lookahead < MIN_LOOKAHEAD && flush == Z_NO_FLUSH) {
                    return block_state::need_more;
                }
                if unlikely(lookahead == 0) {
                    break; /* flush the current block */
                }
            }
            // Each counter is read once per pass and kept in a local. Updating both in place lets
            // the compiler merge them into one 8-byte load, which stalls after separate stores.
            let strstart = (*s).strstart;

            /* Insert the string window[strstart .. strstart+2] in the
             * dictionary, and set hash_head to the head of the hash chain:
             */
            if likely(lookahead >= WANT_MATCH) {
                // Read what the checks below need before the insert stores into the tables.
                let max_dist = i64::from(max_dist(s));
                let str_val = u32::from_le(zng_memread_4(window.add(strstart as usize)));
                let hash_head = insert_knuth_val(s, strstart, str_val);
                let dist = i64::from(strstart) - i64::from(hash_head);
                lc = str_val as u8;

                /* Find the longest match.
                 * At this point we have always match length < WANT_MIN_MATCH
                 */
                if dist <= max_dist && dist > 0 && hash_head != 0 {
                    /* To simplify the code, we prevent matches with the string
                     * of window index 0 (in particular we have to avoid a match
                     * of the string with itself at the start of the input file).
                     */
                    match_len = functable::longest_match(s, hash_head);
                    /* longest_match() sets match_start */
                }
            } else {
                lc = *window.add(strstart as usize);
            }

            /* set if current block must be flushed */
            let bflush = if match_len >= WANT_MATCH {
                debug_assert!(
                    strstart <= u32::from(u16::MAX),
                    "strstart should fit in uint16_t"
                );
                debug_assert!(
                    (*s).match_start <= u32::from(u16::MAX),
                    "match_start should fit in uint16_t"
                );
                check_match(s, strstart, (*s).match_start, match_len);

                let bflush =
                    zng_tr_tally_dist(s, strstart - (*s).match_start, match_len - MIN_MATCH);

                lookahead -= match_len;
                (*s).lookahead = lookahead;

                /* Insert new strings in the hash table only if the match length
                 * is not too large. This saves time but degrades compression.
                 */
                if match_len <= (*s).max_lazy_match && lookahead >= WANT_MATCH {
                    match_len -= 1; /* string at strstart already in table */

                    (*s).strstart = strstart + 1 + match_len;
                    insert_knuth_batch_static(s, window, strstart + 1, match_len);
                } else {
                    (*s).strstart = strstart + match_len;
                    insert_knuth(s, window, strstart + match_len + 2 - MIN_MATCH);

                    /* If lookahead < STD_MIN_MATCH, ins_h is garbage, but it does not
                     * matter since it will be recomputed at next deflate call.
                     */
                }
                match_len = 0;
                bflush
            } else {
                /* No match, output a literal byte */
                let bflush = zng_tr_tally_lit(s, lc);
                (*s).lookahead = lookahead - 1;
                (*s).strstart = strstart + 1;
                bflush
            };
            if unlikely(bflush) {
                flush_block!(s, window, false);
            }
        }
        (*s).insert = if (*s).strstart < MIN_MATCH - 1 {
            (*s).strstart
        } else {
            MIN_MATCH - 1
        };

        if unlikely(flush == Z_FINISH) {
            flush_block!(s, window, true);
            return block_state::finish_done;
        }
        if unlikely((*s).sym_next != 0) {
            flush_block!(s, window, false);
        }
        block_state::block_done
    }
}
