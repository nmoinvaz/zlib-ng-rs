//! deflate_rle.c -- compress data using RLE strategy of deflation algorithm
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_int;

use crate::compare256_rle::compare256_rle;
use crate::deflate::{block_state, deflate_state, fill_window};
use crate::deflate_p::{check_match, flush_block, zng_tr_tally_dist, zng_tr_tally_lit};
use crate::zbuild::{likely, unlikely};
use crate::zlib::{Z_FINISH, Z_NO_FLUSH};
use crate::zutil::{STD_MAX_MATCH, STD_MIN_MATCH};

/* ===========================================================================
 * For Z_RLE, simply look for runs of bytes, generate matches only of distance
 * one.  Do not maintain a hash table.  (It will be regenerated if this run of
 * deflate switches away from Z_RLE.)
 */
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deflate_rle(s: *mut deflate_state, flush: c_int) -> block_state {
    const MIN_MATCH: u32 = STD_MIN_MATCH as u32;
    const MAX_MATCH: u32 = STD_MAX_MATCH as u32;

    // SAFETY: the caller guarantees the state is valid. fill_window keeps lookahead bytes
    // available at strstart, with STD_MAX_MATCH readable bytes after them.
    unsafe {
        let window = (*s).window;
        let mut match_len = 0;
        let mut lookahead = (*s).lookahead;
        let mut strstart = (*s).strstart;

        loop {
            /* Make sure that we always have enough lookahead, except
             * at the end of the input file. We need STD_MAX_MATCH bytes
             * for the longest run, plus one for the unrolled loop.
             */
            if unlikely(lookahead <= MAX_MATCH) {
                (*s).lookahead = lookahead;
                (*s).strstart = strstart;
                fill_window(s);
                lookahead = (*s).lookahead;
                strstart = (*s).strstart;
                if unlikely(lookahead <= MAX_MATCH && flush == Z_NO_FLUSH) {
                    return block_state::need_more;
                }
                if unlikely(lookahead == 0) {
                    break; /* flush the current block */
                }
            }

            /* See how many times the previous byte repeats */
            if likely(lookahead >= MIN_MATCH && strstart > 0) {
                /* scan goes up to strend for length of run */
                let scan = window.add(strstart as usize - 1);
                if *scan == *scan.add(1) && *scan.add(1) == *scan.add(2) {
                    match_len = compare256_rle(*scan.cast(), &*scan.add(3).cast()) + 2;
                    match_len = match_len.min(lookahead);
                }
                debug_assert!(
                    scan.add(match_len as usize) <= window.add((*s).window_size as usize - 1),
                    "wild scan"
                );
            }

            /* Emit match if have run of STD_MIN_MATCH or longer, else emit literal */
            /* set if current block must be flushed */
            let bflush = if match_len >= MIN_MATCH {
                debug_assert!(
                    strstart <= u32::from(u16::MAX),
                    "strstart should fit in uint16_t"
                );
                check_match(s, strstart, strstart - 1, match_len);

                let bflush = zng_tr_tally_dist(s, 1, match_len - MIN_MATCH);

                lookahead -= match_len;
                strstart += match_len;
                match_len = 0;
                bflush
            } else {
                /* No match, output a literal byte */
                let bflush = zng_tr_tally_lit(s, *window.add(strstart as usize));
                lookahead -= 1;
                strstart += 1;
                bflush
            };
            if bflush {
                (*s).lookahead = lookahead;
                (*s).strstart = strstart;
                flush_block!(s, window, false);
            }
        }
        (*s).lookahead = lookahead;
        (*s).strstart = strstart;
        (*s).insert = 0;
        if flush == Z_FINISH {
            flush_block!(s, window, true);
            return block_state::finish_done;
        }
        if (*s).sym_next != 0 {
            flush_block!(s, window, false);
        }
        block_state::block_done
    }
}
