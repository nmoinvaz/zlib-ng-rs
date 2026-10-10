//! deflate_medium.c -- The deflate_medium deflate strategy
//! Copyright (C) Hans Kristian Rosbach
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! deflate_medium_tpl.h -- The deflate_medium deflate strategy
//!
//! Copyright (C) 2013 Intel Corporation. All rights reserved.
//! Authors:
//!  Arjan van de Ven    <arjan@linux.intel.com>
//!
//! Copyright (C) 2026 Hans Kristian Rosbach
//!
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_int;
use core::slice;

use crate::deflate::{MIN_LOOKAHEAD, block_state, deflate_state, fill_window, max_dist};
use crate::deflate_p::{check_match, flush_block, zng_tr_tally_dist, zng_tr_tally_lit};
use crate::functable;
use crate::insert_string::insert_knuth_batch;
use crate::insert_string_p::insert_knuth;
use crate::zbuild::{likely, unlikely};
use crate::zlib::{Z_FINISH, Z_NO_FLUSH};
use crate::zutil::{STD_MIN_MATCH, WANT_MIN_MATCH};

const MIN_MATCH: u32 = STD_MIN_MATCH as u32;
const WANT_MATCH: u32 = WANT_MIN_MATCH as u32;

#[derive(Clone, Copy, Default)]
struct Match {
    match_start: u32,
    match_length: u32,
    strstart: u32,
    orgstart: u32,
}

/* insert_match assumes:
 * - s->lookahead > match.match_length + WANT_MIN_MATCH
 * - match_len >= WANT_MIN_MATCH
 */
/// FIZZLE is USE_FIZZLE in the C template.
///
/// # Safety
///
/// `s` must point to a valid deflate_state, `window` must be its window, and the assumptions above
/// must hold.
unsafe fn insert_match<const FIZZLE: bool>(
    s: *mut deflate_state,
    window: *mut u8,
    m: Match,
    max_len: u32,
) {
    let match_len = m.match_length;
    let strstart = m.strstart + 1; // string at strstart already in table
    let end = strstart + match_len - 1;

    /* Insert new strings in the hash table only if the match length
     * is not too large. This saves time but degrades compression.
     */
    let mut start = if unlikely(match_len > max_len) {
        // For too long matches, insert only the tail position.
        end - 1
    } else {
        strstart
    };

    if FIZZLE && unlikely(start < m.orgstart) {
        start = m.orgstart;
    }

    // SAFETY: the caller guarantees the lookahead covers the strings up to end.
    unsafe { insert_knuth_batch(s, window, start, end - start) };
}

/// # Safety
///
/// `s` must point to a valid deflate_state with at least MIN_LOOKAHEAD bytes of lookahead when
/// `hash_head` is not zero.
#[inline(always)]
unsafe fn find_best_match<const FIZZLE: bool>(
    s: *mut deflate_state,
    hash_head: u32,
    max_dist: i32,
) -> Match {
    // SAFETY: the caller guarantees the state is valid for longest_match.
    unsafe {
        let strstart = (*s).strstart;
        let mut m = Match {
            strstart,
            orgstart: if FIZZLE { strstart } else { 0 },
            ..Match::default()
        };

        let dist = (strstart as i32).wrapping_sub(hash_head as i32);
        if dist <= max_dist && dist > 0 && hash_head != 0 {
            /* To simplify the code, we prevent matches with the string
             * of window index 0 (in particular we have to avoid a match
             * of the string with itself at the start of the input file).
             */
            m.match_length = functable::longest_match(s, hash_head);
            m.match_start = (*s).match_start;
            if unlikely(m.match_length < WANT_MATCH) {
                m.match_length = 1;
            }
            if unlikely(m.match_start >= m.strstart) {
                /* this can happen due to some restarts */
                m.match_length = 1;
            }
        } else {
            /* Set up the match to be a 1 byte literal */
            m.match_start = 0;
            m.match_length = 1;
        }

        m
    }
}

/* fizzle_matches investigates whether next_match (which starts after current_match) can grow backwards
 * to absorb current_match entirely, or reduce it to a single literal.
 * This occurs because next_match points to a different historical dictionary position, allowing it to discover
 * a better matching alignment that current_match bypassed due to the medium-strategy skipping positions.
 *
 * fizzle_matches assumes:
 * - current_match.match_length > 1
 * - current_match.match_length - 1 <= next->match_start
 * - current_match.match_length - 1 <= next->strstart
 * - next_match.match_length >= WANT_MIN_MATCH
 *
 * fizzle_matches returns:
 * - If successful, current and next are returned modified.
 *   - current_match.match_length is then either 0, 1
 */
/// # Safety
///
/// `window` must be the window that both matches refer to, and the assumptions above must hold.
unsafe fn fizzle_matches(window: *mut u8, current: &mut Match, next: &mut Match, max_dist: i32) {
    // SAFETY: the assumptions above keep every offset inside the window.
    unsafe {
        let mut matched = window.add((next.match_start + 1 - current.match_length) as usize);
        let mut orig = window.add((next.strstart + 1 - current.match_length) as usize);

        /* quick exit check.. if this fails then don't bother with anything else */
        if likely(*matched != *orig) {
            return;
        }

        let limit = if next.strstart as i32 > max_dist {
            next.strstart as i32 - max_dist
        } else {
            0
        };

        // Steps needed to successfully fizzle match
        let need = current.match_length - 1;

        // Protect next->strstart from moving past maximum distance
        let max_steps_to_limit = next.strstart as i32 - limit;

        // Protect next->match_length from exceeding 256
        let max_growth_allowed = 256 - next.match_length as i32;

        // Protect next->match_start from going too far back
        let max_steps_to_history = next.match_start as i32 - 1;

        // steps is the max number of backward steps allowed for each limitation
        let steps1 = (current.match_length as i32).min(max_steps_to_limit);
        let steps2 = max_growth_allowed.min(max_steps_to_history);
        let steps = steps1.min(steps2);

        // If we can't possibly fizzle the current match out, return early
        if likely(steps < need as i32) {
            return;
        }

        // The quick exit above already checked the first byte of that range.
        // Compare the whole range here.
        if likely(
            slice::from_raw_parts(matched, need as usize)
                != slice::from_raw_parts(orig, need as usize),
        ) {
            return;
        }

        // Check whether the final extra backward byte is also possible.
        // This decides whether the current match becomes length 1 or 0.
        let extra_byte_ok = steps == current.match_length as i32;

        // Update variables, reduces current->match_length to 1.
        next.match_start -= need;
        next.strstart -= need;
        next.match_length += need;
        next.orgstart += 1;
        current.match_length = 1;

        // If every constraint allowed one more backward byte, test it.
        // If it matches, the current match is fully absorbed and becomes length 0.
        if extra_byte_ok {
            matched = window.add(next.match_start as usize - 1);
            orig = window.add(next.strstart as usize - 1);

            if *matched == *orig {
                next.match_start -= 1;
                next.strstart -= 1;
                next.match_length += 1;
                current.match_length = 0;
            }
        }
    }
}

/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[inline(always)]
unsafe fn deflate_medium_impl<const FIZZLE: bool>(
    s: *mut deflate_state,
    flush: c_int,
) -> block_state {
    // SAFETY: the caller guarantees the state is valid. fill_window keeps MIN_LOOKAHEAD bytes
    // available at strstart except at the end of the input.
    unsafe {
        let mut current_match;
        let mut next_match = Match::default();
        let window_end = (*s).window_size - MIN_LOOKAHEAD;
        let max_len = 16 * (*s).max_lazy_match;
        let window = (*s).window;
        let max_dist = max_dist(s) as i32;

        loop {
            let mut curr_match_len;

            /* Make sure that we always have enough lookahead, except
             * at the end of the input file. We need STD_MAX_MATCH bytes
             * for the next match, plus WANT_MIN_MATCH bytes to insert the
             * string following the next current_match.
             */
            // lookahead is read once per pass and kept in a local, so the table stores below do
            // not force it to be read again.
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
                if FIZZLE {
                    next_match.match_length = 0;
                }
            }

            /* Insert the string window[strstart .. strstart+2] in the
             * dictionary, and set hash_head to the head of the hash chain:
             */

            if FIZZLE {
                /* If we already have a future match from a previous round, just use that */
                if next_match.match_length > 0 {
                    current_match = next_match;
                    next_match.match_length = 0;
                } else {
                    let mut hash_head = 0; /* head of the hash chain */
                    if likely(lookahead >= WANT_MATCH) {
                        hash_head = insert_knuth(s, window, (*s).strstart);
                    }

                    current_match = find_best_match::<FIZZLE>(s, hash_head, max_dist);
                }
                curr_match_len = current_match.match_length;

                if curr_match_len >= WANT_MATCH && lookahead > curr_match_len + WANT_MATCH {
                    insert_match::<FIZZLE>(s, window, current_match, max_len);
                }

                /* now, look ahead one */
                if likely(
                    lookahead > MIN_LOOKAHEAD
                        && (current_match.strstart + curr_match_len) < window_end,
                ) {
                    let strstart = current_match.strstart + curr_match_len;
                    (*s).strstart = strstart;
                    let hash_head = insert_knuth(s, window, strstart);

                    next_match = find_best_match::<FIZZLE>(s, hash_head, max_dist);

                    let tmp_cmatch_len_sub = curr_match_len.wrapping_sub(1);
                    if tmp_cmatch_len_sub != 0
                        && next_match.match_length >= WANT_MATCH
                        && tmp_cmatch_len_sub <= next_match.match_start
                    {
                        fizzle_matches(window, &mut current_match, &mut next_match, max_dist);
                        curr_match_len = current_match.match_length;
                    }

                    (*s).strstart = current_match.strstart;
                    if curr_match_len == 0 {
                        /* If current match fizzled out, jump to next loop iteration */
                        continue;
                    }
                } else {
                    next_match.match_length = 0;
                }
            } else {
                // WITHOUT_FIZZLE: We don't look for future matches, so code is much simplified
                let mut hash_head = 0; /* head of the hash chain */
                if likely(lookahead >= WANT_MATCH) {
                    hash_head = insert_knuth(s, window, (*s).strstart);
                }

                current_match = find_best_match::<FIZZLE>(s, hash_head, max_dist);
                curr_match_len = current_match.match_length;

                if curr_match_len >= WANT_MATCH && lookahead > curr_match_len + WANT_MATCH {
                    insert_match::<FIZZLE>(s, window, current_match, max_len);
                }
            }

            /* now emit the current match */
            // The cursor sits at the start of the current match here, so its new value does not
            // need a read of the old one.
            debug_assert!((*s).strstart == current_match.strstart);
            (*s).lookahead = lookahead - curr_match_len;
            /* set if current block must be flushed */
            let bflush = if likely(curr_match_len == 1) {
                /* matches shorter than WANT_MIN_MATCH are set to 1, we need to emit these as literals */
                zng_tr_tally_lit(s, *window.add(current_match.strstart as usize))
            } else {
                check_match(
                    s,
                    current_match.strstart,
                    current_match.match_start,
                    curr_match_len,
                );
                zng_tr_tally_dist(
                    s,
                    current_match.strstart - current_match.match_start,
                    curr_match_len - MIN_MATCH,
                )
            };

            /* move the "cursor" forward */
            (*s).strstart = current_match.strstart + curr_match_len;

            if unlikely(bflush) {
                flush_block!(s, window, false);
            }
        }

        (*s).insert = if (*s).strstart < MIN_MATCH - 1 {
            (*s).strstart
        } else {
            MIN_MATCH - 1
        };
        if flush == Z_FINISH {
            flush_block!(s, window, true);
            return block_state::finish_done;
        }
        if unlikely((*s).sym_next != 0) {
            flush_block!(s, window, false);
        }

        block_state::block_done
    }
}

// deflate_medium without fizzle, for levels 3-4
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deflate_medium(s: *mut deflate_state, flush: c_int) -> block_state {
    // SAFETY: the caller upholds the contract of deflate_medium_impl.
    unsafe { deflate_medium_impl::<false>(s, flush) }
}

// deflate_medium with fizzle, for levels 5-6
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deflate_medium_fizzle(s: *mut deflate_state, flush: c_int) -> block_state {
    // SAFETY: the caller upholds the contract of deflate_medium_impl.
    unsafe { deflate_medium_impl::<true>(s, flush) }
}
