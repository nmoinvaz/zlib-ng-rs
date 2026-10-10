//! deflate_huff.c -- compress data using huffman encoding only strategy
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_int;

use crate::deflate::{block_state, deflate_state, fill_window};
use crate::deflate_p::{flush_block, zng_tr_tally_lit};
use crate::zbuild::unlikely;
use crate::zlib::{Z_FINISH, Z_NO_FLUSH};

/* ===========================================================================
 * For Z_HUFFMAN_ONLY, do not look for matches.  Do not maintain a hash table.
 * (It will be regenerated if this run of deflate switches away from Huffman.)
 */
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deflate_huff(s: *mut deflate_state, flush: c_int) -> block_state {
    // SAFETY: the caller guarantees the state is valid. fill_window keeps lookahead bytes
    // available at strstart.
    unsafe {
        let window = (*s).window;
        let mut lookahead = (*s).lookahead;
        let mut strstart = (*s).strstart;

        loop {
            /* Make sure that we have a literal to write. */
            if unlikely(lookahead == 0) {
                (*s).lookahead = lookahead;
                (*s).strstart = strstart;
                fill_window(s);
                lookahead = (*s).lookahead;
                strstart = (*s).strstart;
                if unlikely(lookahead == 0) {
                    if flush == Z_NO_FLUSH {
                        return block_state::need_more;
                    }
                    break; /* flush the current block */
                }
            }

            /* Output a literal byte */
            /* set if current block must be flushed */
            let bflush = zng_tr_tally_lit(s, *window.add(strstart as usize));
            lookahead -= 1;
            strstart += 1;
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
