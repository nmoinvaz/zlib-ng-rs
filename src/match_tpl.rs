//! match_tpl.h -- find longest match template for compare256 variants
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! Portions copyright (C) 2014-2021 Konstantin Nosov
//!  Fast-zlib optimized longest_match
//!  https://github.com/gildor2/fast_zlib

use crate::deflate::{Pos, deflate_state, max_dist, w_mask};
use crate::fallback_builtins::{zng_first_bytes_mask64, zng_first_diff_byte64};
use crate::insert_string_p::{update_hash_knuth, update_hash_roll};
use crate::zbuild::unlikely;
use crate::zmemory::{zng_memread_4, zng_memread_8};
use crate::zutil::{STD_MAX_MATCH, STD_MIN_MATCH, WANT_MIN_MATCH};

const EARLY_EXIT_TRIGGER_LEVEL: i32 = 5;

/// The compare256 variant that a longest_match is built around, COMPARE256 in the C template
pub(crate) trait Compare256 {
    /// Returns the length of the common prefix of the two blocks.
    fn compare256(src0: &[u8; 256], src1: &[u8; 256]) -> u32;
}

/* Set match_start to the longest match starting at the given string and
 * return its length. Matches shorter or equal to prev_length are discarded,
 * in which case the result is equal to prev_length and match_start is garbage.
 *
 * IN assertions: cur_match is the head of the hash chain for the current
 * string (strstart) and its distance is <= MAX_DIST, and prev_length >=1
 * OUT assertion: the match length is not greater than s->lookahead
 */
/// SLOW and ROLL select what LONGEST_MATCH_SLOW and LONGEST_MATCH_SLOW_ROLL select in the C
/// template.
///
/// # Safety
///
/// `s` must point to a deflate_state that upholds the IN assertions above, with at least
/// MIN_LOOKAHEAD initialized bytes in the window after strstart.
#[inline(always)]
pub(crate) unsafe fn longest_match<C: Compare256, const SLOW: bool, const ROLL: bool>(
    s: *mut deflate_state,
    mut cur_match: u32,
) -> u32 {
    const MIN_MATCH: u32 = STD_MIN_MATCH as u32;
    const WANT_MATCH: u32 = WANT_MIN_MATCH as u32;

    /* The code is optimized for STD_MAX_MATCH-2 multiple of 16. */
    const { assert!(STD_MAX_MATCH == 258, "Code too clever") };

    // SAFETY: the caller guarantees the state is consistent. Every candidate lies between limit
    // and strstart, so the reads through mbase_start and mbase_end stay inside the window even
    // though the two bases can point before its start.
    unsafe {
        let wmask = w_mask(s);
        let strstart = (*s).strstart;
        let window: *const u8 = (*s).window;
        let prev: *const Pos = (*s).prev;
        let head: *const Pos = (*s).head;
        let mut mbase_start = window;
        let mut chain_length = (*s).max_chain_length;
        let nice_match = (*s).nice_match as u32;
        let lookahead = (*s).lookahead;
        let mut match_offset = 0;

        let mut best_len = if (*s).prev_length != 0 {
            (*s).prev_length
        } else {
            MIN_MATCH - 1
        };
        if unlikely(best_len >= lookahead) {
            return lookahead;
        }
        /* Rolling-hash variant always runs the post-match offset search; the
         * compiler folds the constant away below.
         *
         * The post-match offset search only pays off when we entered with a
         * prior best_len from lazy evaluation, so gate on it at function entry.
         */
        let offset_search = ROLL || best_len >= MIN_MATCH;

        /* Calculate read offset which should only extend an extra byte to find the
         * next best match length. When best_len is shorter than the read width, we
         * diff the mismatched bytes instead.
         */
        let mut offset = if best_len >= 8 { best_len - 7 } else { 0 };

        let scan = window.add(strstart as usize);
        let scan_start = zng_memread_8(scan);
        let mut scan_end = zng_memread_8(scan.add(offset as usize));
        let mut mbase_end = mbase_start.wrapping_add(offset as usize);

        /* Do not waste too much time if we already have a good match */
        if unlikely(best_len >= (*s).good_match) {
            chain_length >>= 2;
        }

        /* Stop when cur_match becomes <= limit. To simplify the code,
         * we prevent matches with the string of window index 0
         */
        let mut limit = if strstart > max_dist(s) {
            strstart - max_dist(s)
        } else {
            0
        };
        let early_exit = (*s).level < EARLY_EXIT_TRIGGER_LEVEL;
        let limit_base = limit;
        if SLOW && best_len >= MIN_MATCH {
            /* We're continuing search (lazy evaluation). Find a most distant
             * chain by hashing substrings within the match area. We cannot use
             * s->prev[strstart+1,...] immediately because those strings are not
             * yet inserted into the hash table.
             */
            if ROLL {
                let mut hash = update_hash_roll(0, *scan.add(1));
                hash = update_hash_roll(hash, *scan.add(2));

                for i in 3..=best_len {
                    hash = update_hash_roll(hash, *scan.add(i as usize));
                    let pos = u32::from(*head.add(hash as usize));
                    if unlikely(pos < cur_match) {
                        match_offset = i - 2;
                        cur_match = pos;
                    }
                }
            } else {
                /* 4-byte Knuth hash, fresh lookup per offset */
                let mut i = 1;
                while i + (WANT_MATCH - 1) <= best_len {
                    let val = u32::from_le(zng_memread_4(scan.add(i as usize)));
                    let hash = update_hash_knuth(val);
                    let pos = u32::from(*head.add(hash as usize));
                    if pos < cur_match {
                        match_offset = i;
                        cur_match = pos;
                    }
                    i += 1;
                }
            }

            /* Update offset-dependent variables */
            limit = limit_base + match_offset;
            if unlikely(cur_match <= limit) {
                return best_len;
            }
            mbase_start = mbase_start.wrapping_sub(match_offset as usize);
            mbase_end = mbase_end.wrapping_sub(match_offset as usize);
        }
        loop {
            if unlikely(cur_match >= strstart) {
                break;
            }

            /* Skip to next match if the match length cannot increase or if the match length is
             * less than 2. Note that the checks below for insufficient lookahead only occur
             * occasionally for performance reasons.
             * Therefore uninitialized memory will be accessed and conditional jumps will be made
             * that depend on those values. However the length of the match is limited to the
             * lookahead, so the output of deflate is not affected by the uninitialized values.
             */
            // The second value is true where the C template jumps to short_match_accept.
            let (len, short_match_accept) = 'candidate: {
                if best_len < 8 {
                    let mut cand_start =
                        zng_memread_8(mbase_start.wrapping_add(cur_match as usize));
                    if scan_start != cand_start {
                        /* Peel the first candidate out of the loop. A full 8-byte match falls
                         * straight through to compare256, and single-candidate chains
                         * (barely-compressible data) run with no loop overhead. */
                        let first_mask = zng_first_bytes_mask64(best_len + 1);
                        let mut diff = scan_start ^ cand_start;
                        /* A candidate beats best_len only when its first best_len+1 bytes match,
                         * i.e. those bytes of the XOR are zero. The masked test rejects without
                         * running ctz. */
                        if unlikely(diff & first_mask == 0) {
                            break 'candidate (zng_first_diff_byte64(diff), true);
                        }
                        chain_length = chain_length.wrapping_sub(1);
                        if chain_length == 0 {
                            return best_len;
                        }
                        cur_match = u32::from(*prev.add((cur_match & wmask) as usize));
                        if cur_match <= limit {
                            return best_len;
                        }
                        cand_start = zng_memread_8(mbase_start.wrapping_add(cur_match as usize));
                        if scan_start != cand_start {
                            /* Walk the remaining candidates with the chain advance kept inline. */
                            loop {
                                diff = scan_start ^ cand_start;
                                if unlikely(diff & first_mask == 0) {
                                    break 'candidate (zng_first_diff_byte64(diff), true);
                                }
                                chain_length = chain_length.wrapping_sub(1);
                                if chain_length == 0 {
                                    return best_len;
                                }
                                cur_match = u32::from(*prev.add((cur_match & wmask) as usize));
                                if cur_match <= limit {
                                    return best_len;
                                }
                                cand_start =
                                    zng_memread_8(mbase_start.wrapping_add(cur_match as usize));
                                if scan_start == cand_start {
                                    break;
                                }
                            }
                        }
                    }
                    /* All 8 bytes match, fallthrough to compare256 for the tail. */
                } else {
                    /* Pre-filter the candidate on the start and end sentinels before compare256
                     * using simple 8-byte comparison since best_len >= 8. */
                    loop {
                        /* First check the end of the candidate at best_len+1 due to the higher
                         * likelihood of a mismatch. */
                        if zng_memread_8(mbase_end.wrapping_add(cur_match as usize)) == scan_end
                            && zng_memread_8(mbase_start.wrapping_add(cur_match as usize))
                                == scan_start
                        {
                            break;
                        }
                        chain_length = chain_length.wrapping_sub(1);
                        if chain_length != 0 {
                            cur_match = u32::from(*prev.add((cur_match & wmask) as usize));
                            if cur_match > limit {
                                continue;
                            }
                        }
                        return best_len;
                    }
                }
                let candidate = mbase_start.wrapping_add(cur_match as usize + 2);
                (
                    C::compare256(&*scan.add(2).cast(), &*candidate.cast()) + 2,
                    false,
                )
            };

            if short_match_accept || len > best_len {
                let match_start = cur_match - match_offset;
                (*s).match_start = match_start;

                /* Do not look for better matches if the current match reaches
                 * or exceeds the end of the input.
                 */
                if unlikely(len >= lookahead) {
                    return lookahead;
                }
                if unlikely(len >= nice_match) {
                    return len;
                }

                best_len = len;

                offset = if best_len >= 8 { best_len - 7 } else { 0 };

                scan_end = zng_memread_8(scan.add(offset as usize));

                /* Look for a better string offset */
                if SLOW
                    && unlikely(offset_search && len > MIN_MATCH && match_start + len < strstart)
                {
                    /* Go back to offset 0 */
                    cur_match -= match_offset;
                    match_offset = 0;
                    let mut next_pos = cur_match;

                    /* Walk prev[] for positions inside the match. The bound keeps
                     * the hash window within the match, so we follow chains that
                     * share bytes with the current match, not data past its end.
                     */
                    /* 4-byte Knuth hash needs len - 4 bound */
                    let bound = if ROLL { MIN_MATCH } else { WANT_MATCH };
                    for i in 0..=len - bound {
                        let pos = u32::from(*prev.add(((cur_match + i) & wmask) as usize));
                        if unlikely(pos < next_pos) {
                            /* Hash chain is more distant, use it */
                            if unlikely(pos <= limit_base + i) {
                                return best_len;
                            }
                            next_pos = pos;
                            match_offset = i;
                        }
                    }
                    /* Switch cur_match to next_pos chain */
                    cur_match = next_pos;

                    /* Try hash head at a window covering the tail of the current
                     * match to find chains that extend farther back. The window
                     * width differs per variant: 3 bytes for rolling, 4 for Knuth.
                     */
                    if ROLL {
                        let scan_endstr = scan.add((len - (MIN_MATCH - 1)) as usize);

                        let mut hash = update_hash_roll(0, *scan_endstr);
                        hash = update_hash_roll(hash, *scan_endstr.add(1));
                        hash = update_hash_roll(hash, *scan_endstr.add(2));

                        let pos = u32::from(*head.add(hash as usize));
                        if unlikely(pos < cur_match) {
                            match_offset = len - (MIN_MATCH - 1);
                            if pos <= limit_base + match_offset {
                                return best_len;
                            }
                            cur_match = pos;
                        }
                    } else {
                        let scan_endstr = scan.add((len - WANT_MATCH) as usize);
                        let val = u32::from_le(zng_memread_4(scan_endstr));
                        let hash = update_hash_knuth(val);

                        let pos = u32::from(*head.add(hash as usize));
                        if pos < cur_match {
                            match_offset = len - WANT_MATCH;
                            if pos <= limit_base + match_offset {
                                return best_len;
                            }
                            cur_match = pos;
                        }
                    }

                    /* Update offset-dependent variables */
                    limit = limit_base + match_offset;
                    mbase_start = window.wrapping_sub(match_offset as usize);
                    mbase_end = mbase_start.wrapping_add(offset as usize);
                    continue;
                }
                mbase_end = mbase_start.wrapping_add(offset as usize);
            } else if !SLOW && unlikely(early_exit) {
                /* The probability of finding a match later if we here is pretty low, so for
                 * performance it's best to outright stop here for the lower compression levels
                 */
                break;
            }
            chain_length = chain_length.wrapping_sub(1);
            if chain_length != 0 {
                cur_match = u32::from(*prev.add((cur_match & wmask) as usize));
                if cur_match > limit {
                    continue;
                }
            }
            return best_len;
        }
        best_len
    }
}
