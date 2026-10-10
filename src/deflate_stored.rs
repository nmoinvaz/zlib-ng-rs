//! deflate_stored.c -- store data without compression using deflation algorithm
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::{c_int, c_ulong};
use core::ptr;

use crate::deflate::{
    block_state, cmpr_bits_add, deflate_state, flush_pending, put_short, sent_bits_add,
};
use crate::deflate_p::{MAX_STORED, read_buf};
use crate::trees::zng_tr_stored_block;
use crate::zbuild::z_uintmax_t;
use crate::zlib::{Z_FINISH, Z_NO_FLUSH};

/* ===========================================================================
 * Copy without compression as much as possible from the input stream, return
 * the current block state.
 *
 * deflate_stored() is written to minimize the number of times an input byte is
 * copied. It is most efficient with large input and output buffers, which
 * maximizes the opportunities to have a single copy from next_in to next_out.
 */
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn deflate_stored(s: *mut deflate_state, flush: c_int) -> block_state {
    // SAFETY: the caller guarantees the state and its stream are valid. Every copy below stays
    // inside the window, the pending buffer, or the avail_in and avail_out bytes of the stream.
    unsafe {
        let strm = (*s).strm;
        let window = (*s).window;
        /* Smallest worthy block size when not flushing or finishing. By default
         * this is 32K. This can be as small as 507 bytes for memLevel == 1. For
         * large input and output buffers, the stored block size will be larger.
         */
        let w_size = (*s).w_size;
        let min_block = ((*s).pending_buf_size - 5).min(w_size);

        /* Copy as many min_block or larger stored blocks directly to next_out as
         * possible. If flushing, copy the remaining available input to next_out as
         * stored blocks, if there is enough space.
         */
        let mut last = false;
        let mut used = (*strm).avail_in;
        loop {
            /* Set len to the maximum size block that we can copy directly with the
             * available input data and output space. Set left to how much of that
             * would be copied from what's left in the window.
             */
            let mut len = MAX_STORED; /* maximum deflate stored block length */
            let mut have = (((*s).bi_valid + 42) >> 3) as u32; /* number of header bytes */
            if (*strm).avail_out < have {
                /* need room for header */
                break;
            }
            /* maximum stored block length that will fit in avail_out: */
            have = (*strm).avail_out - have;
            let mut left = ((*s).strstart as i32 - (*s).block_start) as u32; /* bytes left in window */
            if c_ulong::from(len)
                > c_ulong::from(left).wrapping_add(c_ulong::from((*strm).avail_in))
            {
                len = left.wrapping_add((*strm).avail_in); /* limit len to the input */
            }
            len = len.min(have); /* limit len to the output */

            /* If the stored block would be less than min_block in length, or if
             * unable to copy all of the available input when flushing, then try
             * copying to the window and the pending buffer instead. Also don't
             * write an empty block when flushing -- deflate() does that.
             */
            if len < min_block
                && ((len == 0 && flush != Z_FINISH)
                    || flush == Z_NO_FLUSH
                    || len != left.wrapping_add((*strm).avail_in))
            {
                break;
            }

            /* Make a dummy stored block in pending to get the header bytes,
             * including any pending bits. This also updates the debugging counts.
             */
            last = flush == Z_FINISH && len == left.wrapping_add((*strm).avail_in);
            zng_tr_stored_block(s, ptr::null_mut(), 0, c_int::from(last));

            /* Replace the lengths in the dummy stored block with len. */
            (*s).pending -= 4;
            put_short(s, len as u16);
            put_short(s, !len as u16);

            /* Write the stored block header bytes. */
            flush_pending(strm);

            /* Update debugging counts for the data about to be copied. */
            cmpr_bits_add(s, len << 3);
            sent_bits_add(s, len << 3);

            /* Copy uncompressed bytes from the window to next_out. */
            if left != 0 {
                left = left.min(len);
                ptr::copy_nonoverlapping(
                    window.offset((*s).block_start as isize),
                    (*strm).next_out,
                    left as usize,
                );
                (*strm).next_out = (*strm).next_out.add(left as usize);
                (*strm).avail_out -= left;
                (*strm).total_out = (*strm).total_out.wrapping_add(left as z_uintmax_t);
                (*s).block_start += left as i32;
                len -= left;
            }

            /* Copy uncompressed bytes directly from next_in to next_out, updating
             * the check value.
             */
            if len != 0 {
                read_buf(strm, (*strm).next_out, len);
                (*strm).next_out = (*strm).next_out.add(len as usize);
                (*strm).avail_out -= len;
                (*strm).total_out = (*strm).total_out.wrapping_add(len as z_uintmax_t);
            }
            if last {
                break;
            }
        }

        /* Update the sliding window with the last s->w_size bytes of the copied
         * data, or append all of the copied data to the existing window if less
         * than s->w_size bytes were copied. Also update the number of bytes to
         * insert in the hash tables, in the event that deflateParams() switches to
         * a non-zero compression level. Skip the update when the last block was
         * written, since the window is never read after the stream is finished.
         */
        used -= (*strm).avail_in; /* number of input bytes directly copied */
        if used != 0 && !last {
            /* If any input was used, then no unused input remains in the window,
             * therefore s->block_start == s->strstart.
             */
            if used >= w_size {
                /* supplant the previous history */
                ptr::copy_nonoverlapping(
                    (*strm).next_in.sub(w_size as usize),
                    window,
                    w_size as usize,
                );
                (*s).strstart = w_size;
                (*s).insert = (*s).strstart;
            } else {
                if (*s).window_size - (*s).strstart <= used {
                    /* Slide the window down. */
                    (*s).strstart -= w_size;
                    ptr::copy_nonoverlapping(
                        window.add(w_size as usize),
                        window,
                        (*s).strstart as usize,
                    );
                    (*s).insert = (*s).insert.min((*s).strstart);
                }
                ptr::copy_nonoverlapping(
                    (*strm).next_in.sub(used as usize),
                    window.add((*s).strstart as usize),
                    used as usize,
                );
                (*s).strstart += used;
                (*s).insert += used.min(w_size - (*s).insert);
            }
            (*s).block_start = (*s).strstart as i32;
        }
        (*s).high_water = (*s).high_water.max((*s).strstart);

        /* If the last block was written to next_out, then done. */
        if last {
            (*s).bi_used = 8;
            return block_state::finish_done;
        }

        /* If flushing and all input has been consumed, then done. */
        if flush != Z_NO_FLUSH
            && flush != Z_FINISH
            && (*strm).avail_in == 0
            && (*s).strstart as i32 == (*s).block_start
        {
            return block_state::block_done;
        }

        /* Fill the window with any remaining input. */
        let mut have = (*s).window_size - (*s).strstart;
        if (*strm).avail_in > have && (*s).block_start >= w_size as i32 {
            /* Slide the window down. */
            (*s).block_start -= w_size as i32;
            (*s).strstart -= w_size;
            ptr::copy_nonoverlapping(window.add(w_size as usize), window, (*s).strstart as usize);
            have += w_size; /* more space now */
            (*s).insert = (*s).insert.min((*s).strstart);
        }

        have = have.min((*strm).avail_in);
        if have != 0 {
            read_buf(strm, window.add((*s).strstart as usize), have);
            (*s).strstart += have;
            (*s).insert += have.min(w_size - (*s).insert);
        }
        (*s).high_water = (*s).high_water.max((*s).strstart);

        /* There was not enough avail_out to write a complete worthy or flushed
         * stored block to next_out. Write a stored block to pending instead, if we
         * have enough input for a worthy block, or if flushing and there is enough
         * room for the remaining input as a stored block in the pending buffer.
         */
        have = (((*s).bi_valid + 42) >> 3) as u32; /* number of header bytes */
        /* maximum stored block length that will fit in pending: */
        have = ((*s).pending_buf_size - have).min(MAX_STORED);
        let min_block = have.min(w_size);
        let left = ((*s).strstart as i32 - (*s).block_start) as u32;
        if left >= min_block
            || ((left != 0 || flush == Z_FINISH)
                && flush != Z_NO_FLUSH
                && (*strm).avail_in == 0
                && left <= have)
        {
            let len = left.min(have);
            last = flush == Z_FINISH && (*strm).avail_in == 0 && len == left;
            zng_tr_stored_block(
                s,
                window.offset((*s).block_start as isize),
                len,
                c_int::from(last),
            );
            (*s).block_start += len as i32;
            flush_pending(strm);
        }

        /* We've done all we can with the available input and output. */
        if last {
            (*s).bi_used = 8;
            return block_state::finish_started;
        }
        block_state::need_more
    }
}
