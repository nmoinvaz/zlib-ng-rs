//! deflate_slow.c -- compress data using the slow strategy of deflation algorithm
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_int;

use crate::deflate::{
    MIN_LOOKAHEAD, MIN_ROLL_LEVEL, block_state, deflate_state, fill_window, insert_batch_fn,
    longest_match_fn, max_dist,
};
use crate::deflate_p::{
    check_match, flush_block, flush_block_only, zng_tr_tally_dist, zng_tr_tally_lit,
};
use crate::insert_string_p::{insert_knuth, insert_roll};
use crate::zbuild::{likely, unlikely};
use crate::zlib::{Z_FILTERED, Z_FINISH, Z_NO_FLUSH};
use crate::zutil::{STD_MIN_MATCH, WANT_MIN_MATCH};

/* ===========================================================================
 * Same as deflate_medium, but achieves better compression. We use a lazy
 * evaluation for matches: a match is finally adopted only if there is
 * no better match at the next window position.
 */
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deflate_slow(s: *mut deflate_state, flush: c_int) -> block_state {
    const MIN_MATCH: u32 = STD_MIN_MATCH as u32;
    const WANT_MATCH: u32 = WANT_MIN_MATCH as u32;

    // SAFETY: the caller guarantees the state is valid. fill_window keeps MIN_LOOKAHEAD bytes
    // available at strstart except at the end of the input.
    unsafe {
        let longest_match = longest_match_fn(s);
        let insert_batch = insert_batch_fn(s);
        let window = (*s).window;
        let level = (*s).level;

        /* Matches this long or shorter are discarded. Z_FILTERED ignores lengths up to 5, other
         * strategies discard nothing. */
        let match_discard = if (*s).strategy == Z_FILTERED { 5 } else { 0 };
        /* Same floor for longest_match, kept below good_match. */
        let match_floor = match_discard.min((*s).good_match.wrapping_sub(1));

        /* Process the input block. */
        loop {
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
            // Each counter is read once per pass and kept in a local, so the table stores below do
            // not force them to be read again.
            let strstart = (*s).strstart;

            /* Insert the string window[strstart .. strstart+2] in the
             * dictionary, and set hash_head to the head of the hash chain:
             */
            let mut hash_head = 0;
            if likely(lookahead >= WANT_MATCH) {
                hash_head = if level >= MIN_ROLL_LEVEL {
                    insert_roll(s, window, strstart)
                } else {
                    insert_knuth(s, window, strstart)
                };
            }

            /* Find the longest match, discarding those <= prev_length.
             */
            let prev_match = (*s).match_start;
            (*s).prev_match = prev_match;
            let prev_length = (*s).prev_length;
            let mut match_len = MIN_MATCH - 1;
            let dist = i64::from(strstart) - i64::from(hash_head);

            if dist <= i64::from(max_dist(s))
                && dist > 0
                && prev_length < (*s).max_lazy_match
                && hash_head != 0
            {
                /* To simplify the code, we prevent matches with the string
                 * of window index 0 (in particular we have to avoid a match
                 * of the string with itself at the start of the input file).
                 */

                /* longest_match only looks for matches longer than s->prev_length. */
                (*s).prev_length = prev_length.max(match_floor);
                match_len = longest_match(s, hash_head);
                /* Restore the real previous length, the lazy evaluation below relies on it. */
                (*s).prev_length = prev_length;
                /* longest_match() sets match_start */

                if match_len <= match_discard {
                    /* Match not long enough, treat it as no match found, which makes a garbage
                     * match_start that is harmless. */
                    match_len = MIN_MATCH - 1;
                }
            }
            /* If there was a match at the previous step and the current
             * match is not better, output the previous match:
             */
            if prev_length >= MIN_MATCH && match_len <= prev_length {
                let max_insert = (strstart + lookahead).wrapping_sub(MIN_MATCH);
                /* Do not insert strings in hash table beyond this. */

                debug_assert!(
                    strstart - 1 <= u32::from(u16::MAX),
                    "strstart-1 should fit in uint16_t"
                );
                check_match(s, strstart - 1, prev_match, prev_length);

                /* set if current block must be flushed */
                let bflush =
                    zng_tr_tally_dist(s, strstart - 1 - prev_match, prev_length - MIN_MATCH);

                /* Insert in hash table all strings up to the end of the match.
                 * strstart-1 and strstart are already inserted. If there is not
                 * enough lookahead, the last two strings are not inserted in
                 * the hash table.
                 */
                let prev_length = prev_length - 1;
                (*s).lookahead = lookahead - prev_length;

                let mov_fwd = prev_length - 1;
                if max_insert > strstart {
                    let mut insert_cnt = mov_fwd;
                    if unlikely(insert_cnt > max_insert - strstart) {
                        insert_cnt = max_insert - strstart;
                    }
                    insert_batch(s, window, strstart + 1, insert_cnt);
                }
                (*s).prev_length = 0;
                (*s).match_available = 0;
                (*s).strstart = strstart + mov_fwd + 1;

                if unlikely(bflush) {
                    flush_block!(s, window, false);
                }
            } else if (*s).match_available != 0 {
                /* If there was no match at the previous position, output a
                 * single literal. If there was a match but the current match
                 * is longer, truncate the previous match to a single literal.
                 */
                let bflush = zng_tr_tally_lit(s, *window.add(strstart as usize - 1));
                if unlikely(bflush) {
                    flush_block_only(s, window, false);
                }
                (*s).prev_length = match_len;
                (*s).strstart = strstart + 1;
                (*s).lookahead = lookahead - 1;
                if unlikely((*(*s).strm).avail_out == 0) {
                    return block_state::need_more;
                }
            } else {
                /* There is no previous match to compare with, wait for
                 * the next step to decide.
                 */
                (*s).prev_length = match_len;
                (*s).match_available = 1;
                (*s).strstart = strstart + 1;
                (*s).lookahead = lookahead - 1;
            }
        }
        debug_assert!(flush != Z_NO_FLUSH, "no flush?");
        if unlikely((*s).match_available != 0) {
            let _ = zng_tr_tally_lit(s, *window.add((*s).strstart as usize - 1));
            (*s).match_available = 0;
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
