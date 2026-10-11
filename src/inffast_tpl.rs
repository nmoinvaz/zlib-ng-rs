//! inffast.c -- fast decoding
//! Copyright (C) 1995-2017 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! The C template takes its chunk functions from macros. Here the chunk type and the safe mode
//! are parameters of one generic function.

use crate::chunkset_tpl::{Chunk, chunkcopy, chunkcopy_safe, chunkmemset, chunksize, chunkunroll};
use crate::inflate::{MATCH, TYPE, inflate_state};
use crate::inflate_p::{
    INFLATE_FAST_MIN_HAVE, INFLATE_FAST_MIN_LEFT, INFLATE_FAST_MIN_SAFE, bits_t, load_64_bits,
    set_bad,
};
use crate::inftrees::code;
use crate::zbuild::{likely, unlikely};
use crate::zlib::z_stream;
use crate::zutil::{MAX_BITS, MAX_DIST_EXTRA_BITS, MAX_LEN_ROOT_BITS};

/// A table entry in one register, the way the decoding loop holds it
#[derive(Clone, Copy)]
struct Here(u32);

impl Here {
    /// Reads an entry as one value and makes the compiler treat it as modified, which is what
    /// Z_TOUCH does in C. This keeps the load from being split up or reordered, so the latency
    /// chains of the hot path stay as written.
    ///
    /// # Safety
    ///
    /// `table` must hold more than `index` entries.
    #[inline(always)]
    unsafe fn load(table: *const code, index: usize) -> Self {
        // SAFETY: the caller guarantees the entry. It has the size of a u32 and half its
        // alignment.
        #[allow(unused_mut)]
        let mut here = unsafe { table.add(index).cast::<u32>().read_unaligned() };
        // SAFETY: the empty assembly only names a register.
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("/* {0:w} */", inout(reg) here, options(pure, nomem, nostack, preserves_flags));
        }
        // SAFETY: the empty assembly only names a register. C compilers take the flags as
        // clobbered by every assembly statement on x86, so the same holds here.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            core::arch::asm!("/* {0:e} */", inout(reg) here, options(pure, nomem, nostack));
        }
        Self(here)
    }

    /// bits in this part of the code
    #[inline(always)]
    fn bits(self) -> u32 {
        if cfg!(target_endian = "little") {
            self.0 & 0xff
        } else {
            self.0 >> 24
        }
    }

    /// operation, extra bits, table bits
    #[inline(always)]
    fn op(self) -> u32 {
        if cfg!(target_endian = "little") {
            (self.0 >> 8) & 0xff
        } else {
            (self.0 >> 16) & 0xff
        }
    }

    /// offset in table or code value
    #[inline(always)]
    fn val(self) -> u32 {
        if cfg!(target_endian = "little") {
            self.0 >> 16
        } else {
            self.0 & 0xffff
        }
    }
}

/* Extract extra bits value from saved bit accumulator */
#[inline(always)]
fn extra_bits(old: u64, here: Here, op: u32) -> u32 {
    ((old & ((1u64 << here.bits()) - 1)) >> (op & MAX_BITS as u32)) as u32
}

/*
  Decode literal, length, and distance codes and write out the resulting
  literal and match bytes until either not enough input or output is
  available, an end-of-block is encountered, or a data error is encountered.
  When large enough input and output buffers are supplied to inflate(), for
  example, a 16K input buffer and a 64K output buffer, more than 95% of the
  inflate execution time is spent in this routine.

  Entry assumptions:

       state->mode == LEN
       strm->avail_in >= INFLATE_FAST_MIN_HAVE
       strm->avail_out >= INFLATE_FAST_MIN_LEFT
       start >= strm->avail_out
       state->bits < 8

  On return, state->mode is one of:

       LEN -- ran out of enough output space or enough available input
       TYPE -- reached end of block code, inflate() to interpret next block
       BAD -- error in block data

  Notes:

   - The maximum input bits used by a length/distance pair is 15 bits for the
     length code, 5 bits for the length extra, 15 bits for the distance code,
     and 13 bits for the distance extra.  This totals 48 bits, or six bytes.
     Therefore if strm->avail_in >= 6, then there is enough input to avoid
     checking for available input while decoding.

   - On some architectures, it can be significantly faster (e.g. up to 1.2x
     faster on x86_64) to load from strm->next_in 64 bits, or 8 bytes, at a
     time, so INFLATE_FAST_MIN_HAVE == 8.

   - The maximum bytes that a single length/distance pair can output is 258
     bytes, which is the maximum length that can be coded.  inflate_fast()
     requires strm->avail_out >= 258 for each loop to avoid checking for
     output space.
*/
/// # Safety
///
/// `strm` must be a valid inflate stream that upholds the entry assumptions above, where the
/// safe mode needs INFLATE_FAST_MIN_SAFE bytes of output instead of INFLATE_FAST_MIN_LEFT.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
#[inline(always)]
pub(crate) unsafe fn inflate_fast<C: Chunk, const SAFE: bool>(strm: *mut z_stream, start: u32) {
    /* start: inflate()'s starting value for strm->avail_out */

    /* hold is a local copy of strm->hold. By default, hold satisfies the same
       invariants that strm->hold does, namely that (hold >> bits) == 0. This
       invariant is kept by loading bits into hold one byte at a time, like:

       hold |= next_byte_of_input << bits; in++; bits += 8;

       If we need to ensure that bits >= 15 then this code snippet is simply
       repeated. Over one iteration of the outermost do/while loop, this
       happens up to six times (48 bits of input), as described in the NOTES
       above.

       However, on some little endian architectures, it can be significantly
       faster to load 64 bits once instead of 8 bits six times:

       if (bits <= 16) {
         hold |= next_8_bytes_of_input << bits; in += 6; bits += 48;
       }

       Unlike the simpler one byte load, shifting the next_8_bytes_of_input
       by bits will overflow and lose those high bits, up to 2 bytes' worth.
       The conservative estimate is therefore that we have read only 6 bytes
       (48 bits). Again, as per the NOTES above, 48 bits is sufficient for the
       rest of the iteration, and we will not need to load another 8 bytes.

       Inside this function, we no longer satisfy (hold >> bits) == 0, but
       this is not problematic, even if that overflow does not land on an 8 bit
       byte boundary. Those excess bits will eventually shift down lower as the
       Huffman decoder consumes input, and when new input bits need to be loaded
       into the bits variable, the same input bits will be or'ed over those
       existing bits. A bitwise or is idempotent: (a | b | b) equals (a | b).
       Note that we therefore write that load operation as "hold |= etc" and not
       "hold += etc".

       Outside that loop, at the end of the function, hold is bitwise and'ed
       with (1<<bits)-1 to drop those excess bits so that, on function exit, we
       keep the invariant that (state->hold >> state->bits) == 0.
    */

    // SAFETY: the caller guarantees the stream and the entry assumptions. They leave room for
    // the reads of every refill and for the output of one length/distance pair, and the tables
    // hold every entry that an index of lenbits or distbits bits or a table link can reach.
    unsafe {
        /* copy state to local variables */
        let state = (*strm).state.cast::<inflate_state>();
        /* local strm->next_in */
        let mut input = (*strm).next_in;
        /* have enough input while in < last */
        let last = input.add((*strm).avail_in as usize - (INFLATE_FAST_MIN_HAVE - 1));
        /* local strm->next_out */
        let mut out = (*strm).next_out;
        /* inflate()'s initial strm->next_out */
        let beg = out.sub((start - (*strm).avail_out) as usize);
        /* can use chunkcopy provided out < safe */
        let safe = out.add((*strm).avail_out as usize);
        /* while out < end, enough space available */
        let end = if SAFE {
            safe.sub(INFLATE_FAST_MIN_SAFE - 1)
        } else {
            safe.sub(INFLATE_FAST_MIN_LEFT - 1)
        };
        /* window size or zero if not using window */
        let wsize = (*state).wsize;
        /* valid bytes in the window */
        let whave = (*state).whave;
        /* window write index */
        let wnext = (*state).wnext;
        /* allocated sliding window, if wsize != 0 */
        let window = (*state).window;
        /* local strm->hold */
        let mut hold = (*state).hold;
        /* local strm->bits */
        let mut bits = (*state).bits as bits_t;
        /* local strm->lencode */
        let lcode = (*state).lencode;
        /* local strm->distcode */
        let dcode = (*state).distcode;
        /* mask for first level of length codes */
        let lmask = (1u32 << (*state).lenbits) - 1;
        /* mask for first level of distance codes */
        let dmask = (1u32 << (*state).distbits) - 1;
        /* retrieved table entry */
        let mut here: Here;
        /* code bits, operation, extra bits, or window position, window bytes to copy */
        let mut op: u32;
        /* match length, unused bytes */
        let mut len: u32;
        /* where to copy match from */
        let mut from: *const u8;
        /* match distance */
        let mut dist: u32;
        /* look-behind buffer for extra bits */
        let mut old: u64;

        /* Refill to have at least 56 bits in the bit accumulator */
        macro_rules! refill {
            () => {
                hold |= load_64_bits(input, u32::from(bits));
                input = input.add(((63 ^ u32::from(bits)) >> 3) as usize);
                bits |= 56;
            };
        }
        /* Remove n bits from the bit accumulator */
        macro_rules! dropbits {
            ($n:expr) => {
                let n: u32 = $n;
                hold >>= n;
                bits = bits.wrapping_sub(n as bits_t);
            };
        }

        /* Ensure enough bits for the first length table lookup. Every refill after
        this one is issued behind a table lookup that only needs bits already in
        hold, so the refill's load latency overlaps with the table load instead
        of feeding it. */
        refill!();

        /* decode literals and length/distances until end-of-block or not enough
        input data or output space */
        'decode: loop {
            // Leaving this block continues with the next code, like continue in the C loop.
            'next: {
                /* This lookup needs bits >= MAX_LEN_ROOT_BITS, which every path here
                guarantees: each refill leaves bits >= 56, the literal-only paths
                loop after consuming at most 35 bits, and the distance path refills
                to at least MAX_BITS + MAX_DIST_EXTRA_BITS + MAX_LEN_ROOT_BITS
                before consuming at most MAX_BITS + MAX_DIST_EXTRA_BITS. */
                here = Here::load(lcode, (hold & u64::from(lmask)) as usize);
                /* No-op on the first iteration: the pre-loop refill already filled hold
                and the lookup above consumes nothing, so bits is still >= 56. Tops
                hold back up on every later iteration. */
                refill!();
                old = hold;
                dropbits!(here.bits());
                if likely(here.op() == 0) {
                    *out = here.val() as u8;
                    out = out.add(1);
                    here = Here::load(lcode, (hold & u64::from(lmask)) as usize);
                    old = hold;
                    dropbits!(here.bits());
                    if likely(here.op() == 0) {
                        *out = here.val() as u8;
                        out = out.add(1);
                        here = Here::load(lcode, (hold & u64::from(lmask)) as usize);
                        old = hold;
                        dropbits!(here.bits());
                        if likely(here.op() == 0) {
                            *out = here.val() as u8;
                            out = out.add(1);
                            break 'next;
                        }
                    }
                }
                op = here.op();
                if unlikely(op & 16 == 0) {
                    // The entry is no length base. Walk the table links until one is, or until
                    // a literal, the end of the block or an invalid code ends this code.
                    loop {
                        if unlikely((op & 64) == 0) {
                            /* 2nd level length code */
                            let index = here.val() as usize + (hold & ((1u64 << op) - 1)) as usize;
                            here = Here::load(lcode, index);
                            old = hold;
                            dropbits!(here.bits());
                            if likely(here.op() == 0) {
                                *out = here.val() as u8;
                                out = out.add(1);
                                break 'next;
                            }
                            op = here.op();
                            if likely(op & 16 != 0) {
                                break;
                            }
                        } else if unlikely(op & 32 != 0) {
                            /* end-of-block */
                            (*state).mode = TYPE;
                            break 'decode;
                        } else {
                            set_bad(strm, state, c"invalid literal/length code");
                            break 'decode;
                        }
                    }
                }

                /* length base */
                len = here.val() + extra_bits(old, here, op);
                here = Here::load(dcode, (hold & u64::from(dmask)) as usize);
                /* Reserve bits for the distance code and its extra bits, plus the
                next iteration's length table lookup, which happens before the
                next refill. */
                if unlikely(
                    u32::from(bits) < MAX_BITS as u32 + MAX_DIST_EXTRA_BITS + MAX_LEN_ROOT_BITS,
                ) {
                    refill!();
                }
                loop {
                    old = hold;
                    dropbits!(here.bits());
                    op = here.op();
                    if likely(op & 16 != 0) {
                        break;
                    }
                    if unlikely((op & 64) == 0) {
                        /* 2nd level distance code */
                        let index = here.val() as usize + (hold & ((1u64 << op) - 1)) as usize;
                        here = Here::load(dcode, index);
                    } else {
                        set_bad(strm, state, c"invalid distance code");
                        break 'decode;
                    }
                }

                /* distance base */
                dist = here.val() + extra_bits(old, here, op);
                #[cfg(feature = "inflate-strict")]
                if unlikely(dist > (*state).dmax) {
                    set_bad(strm, state, c"invalid distance too far back");
                    break 'decode;
                }

                if SAFE {
                    /* If there isn't enough output space for the full copy, bail to the
                    slow path's MATCH state which handles partial copies. */
                    if unlikely(len > safe.offset_from_unsigned(out) as u32) {
                        (*state).mode = MATCH;
                        (*state).length = len;
                        (*state).offset = dist;
                        break 'decode;
                    }
                }

                /* max distance in output */
                op = out.offset_from_unsigned(beg) as u32;
                if unlikely(dist > op) {
                    /* see if copy from window */
                    /* distance back in window */
                    op = dist - op;
                    if unlikely(op > whave) {
                        #[cfg(feature = "inflate-allow-invalid-dist")]
                        {
                            if likely((*state).sane != 0) {
                                set_bad(strm, state, c"invalid distance too far back");
                                break 'decode;
                            }
                            let gap = op - whave;
                            let zeros = len.min(gap);
                            /* fill missing bytes with zeros */
                            core::ptr::write_bytes(out, 0, zeros as usize);
                            out = out.add(zeros as usize);
                            len -= zeros;
                            if unlikely(len == 0) {
                                break 'next;
                            }
                            op = whave;
                            if unlikely(op == 0) {
                                /* copy from already-decoded output */
                                out = crate::inflate_p::chunkcopy_safe(
                                    out,
                                    out.sub(dist as usize),
                                    len as usize,
                                    safe,
                                );
                                break 'next;
                            }
                        }
                        #[cfg(not(feature = "inflate-allow-invalid-dist"))]
                        {
                            set_bad(strm, state, c"invalid distance too far back");
                            break 'decode;
                        }
                    }
                    from = window;
                    if likely(wnext == 0) {
                        /* very common case */
                        from = from.add((wsize - op) as usize);
                    } else if likely(wnext >= op) {
                        /* contiguous in window */
                        from = from.add((wnext - op) as usize);
                    } else {
                        /* wrap around window */
                        op -= wnext;
                        from = from.add((wsize - op) as usize);
                        if unlikely(op < len) {
                            /* some from end of window */
                            len -= op;
                            out = chunkcopy_safe::<C>(out, from, op as usize, safe);
                            /* more from start of window */
                            from = window;
                            op = wnext;
                            /* This (rare) case can create a situation where
                            the first chunkcopy below must be checked.
                            */
                        }
                    }
                    if unlikely(op < len) {
                        /* still need some from output */
                        len -= op;
                        if SAFE {
                            // The chunk types built from Rust have no masked reads and writes.
                            out = crate::inflate_p::chunkcopy_safe(out, from, op as usize, safe);
                            out = crate::inflate_p::chunkcopy_safe(
                                out,
                                out.sub(dist as usize),
                                len as usize,
                                safe,
                            );
                        } else {
                            out = chunkcopy_safe::<C>(out, from, op as usize, safe);
                            out = chunkunroll::<C>(out, &mut dist, &mut len);
                            out = chunkcopy_safe::<C>(
                                out,
                                out.sub(dist as usize),
                                len as usize,
                                safe,
                            );
                        }
                    } else if SAFE {
                        out = crate::inflate_p::chunkcopy_safe(out, from, len as usize, safe);
                    } else {
                        out = chunkcopy_safe::<C>(out, from, len as usize, safe);
                    }
                } else if SAFE {
                    out = crate::inflate_p::chunkcopy_safe(
                        out,
                        out.sub(dist as usize),
                        len as usize,
                        safe,
                    );
                } else {
                    /* Whole reference is in range of current output.  No range checks are
                       necessary because we start with room for at least 258 bytes of output,
                       so unroll and roundoff operations can write beyond `out+len` so long
                       as they stay within 258 bytes of `out`.
                    */
                    // C marks this LIKELY. The hint here is stronger, and with it the compiler
                    // spills more of the loop state around the call below, which shows on data
                    // that is full of short distances.
                    if dist >= len || dist as usize >= chunksize::<C>() {
                        out = chunkcopy::<C>(out, out.sub(dist as usize), len as usize);
                    } else {
                        out = chunkmemset::<C>(out, out.sub(dist as usize), len as usize);
                    }
                }
            }
            if !(input < last && out < end) {
                break;
            }
        }

        /* return unused bytes (on entry, bits < 8, so in won't go too far back) */
        len = u32::from(bits) >> 3;
        input = input.sub(len as usize);
        bits = bits.wrapping_sub((len << 3) as bits_t);
        hold &= (1u64 << bits) - 1;

        /* update state and return */
        (*strm).next_in = input;
        (*strm).next_out = out;
        (*strm).avail_in = if input < last {
            ((INFLATE_FAST_MIN_HAVE - 1) + last.offset_from_unsigned(input)) as u32
        } else {
            ((INFLATE_FAST_MIN_HAVE - 1) - input.offset_from_unsigned(last)) as u32
        };
        (*strm).avail_out = safe.offset_from_unsigned(out) as u32;

        debug_assert!(u32::from(bits) <= 32, "Remaining bits greater than 32");
        (*state).hold = u64::from(hold as u32);
        (*state).bits = u32::from(bits);
    }
}

/*
  inflate_fast() speedups that turned out slower (on a PowerPC G3 750CXe):
  - Using bit fields for code structure
  - Different op definition to avoid & for extra bits (do & for table bits)
  - Three separate decoding do-loops for direct, window, and wnext == 0
  - Special case for distance > 1 copies to do overlapped load and store copy
  - Explicit branch predictions (based on measured branch probabilities)
  - Deferring match copy and interspersed it with decoding subsequent codes
  - Swapping literal/length else
  - Swapping window/direct else
  - Larger unrolled copy loops (three is about right)
  - Moving len -= 3 statement into middle of loop
*/
