//! inflate_p.h -- Private inline functions and macros shared with more than one deflate method

use core::ffi::CStr;
use core::ptr;

use crate::inflate::{BAD, inflate_state};
use crate::inftrees::code;
use crate::zlib::z_stream;
use crate::zmemory::zng_memread_8;

/* Huffman code table entry format for length/distance codes (op & 16 set):
 *   bits = code_bits + extra_bits (combined for single-shift decode)
 *   op   = 16 | code_bits
 *   val  = base value
 *
 * For literals (op == 0): bits = code_bits, val = literal byte
 */

/* Extract code size from a Huffman table entry */
#[inline(always)]
pub(crate) fn code_bits(here: code) -> u32 {
    if here.op & 16 != 0 {
        u32::from(here.op & 15)
    } else {
        u32::from(here.bits)
    }
}

/* Extract extra bits count from a length/distance code entry */
#[inline(always)]
pub(crate) fn code_extra(here: code) -> u32 {
    if here.op & 16 != 0 {
        u32::from(here.bits).wrapping_sub(u32::from(here.op & 15))
    } else {
        0
    }
}

/* Build combined op field: preserves extra if not len/dist, else combines with code_bits */
#[inline(always)]
pub(crate) fn combine_op(extra: u32, code_bits: u8) -> u8 {
    if extra & 16 != 0 {
        code_bits | 16
    } else {
        extra as u8
    }
}

/* Build combined bits field: code_bits + extra_bits from extra's low nibble */
#[inline(always)]
pub(crate) fn combine_bits(code_bits: u8, extra: u32) -> u8 {
    code_bits.wrapping_add((extra & 15) as u8)
}

/* Compiler optimization for bit accumulator on x86 architectures */
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(non_camel_case_types)]
pub(crate) type bits_t = u8;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[allow(non_camel_case_types)]
pub(crate) type bits_t = u32;

/* Set mode=BAD and prepare error message */
/// # Safety
///
/// `strm` and `state` must be valid for writes.
#[inline(always)]
pub(crate) unsafe fn set_bad(
    strm: *mut z_stream,
    state: *mut inflate_state,
    errmsg: &'static CStr,
) {
    // SAFETY: the caller guarantees both pointers.
    unsafe {
        (*state).mode = BAD;
        (*strm).msg = errmsg.as_ptr();
    }
}

/* inflate_fast() executes at most two 8-byte refill reads per iteration: the
first at the input position validated by the loop bound (advancing at most
7 bytes), the second therefore ending at most 15 bytes past that position.
The refill before the loop reads at the entry position and advances exactly
7 bytes (entry guarantees bits < 8), so the first iteration stays within
the same bound. */
pub(crate) const INFLATE_FAST_MIN_HAVE: usize = 15;
/// max output per token (258) + 2
pub(crate) const INFLATE_FAST_MIN_LEFT: usize = 260;
/// max unchecked literal writes per iteration
pub(crate) const INFLATE_FAST_MIN_SAFE: usize = 3;

/* Load 64 bits from IN and place the bytes at offset BITS in the result. */
/// # Safety
///
/// `input` must be valid for reads of 8 bytes.
#[inline(always)]
pub(crate) unsafe fn load_64_bits(input: *const u8, bits: u32) -> u64 {
    // SAFETY: the caller guarantees input is valid for reads of 8 bytes.
    let chunk = unsafe { zng_memread_8(input) };
    u64::from_le(chunk) << bits
}

/* Behave like chunkcopy, but avoid writing beyond of legal output. */
/* Inlining chunkcopy_safe into inflate_fast's safe variant helps small output buffers,
but only clang on 64-bit ARM needs the hint. GCC already inlines it, and on x86-64
inlining nearly doubles the safe variant for no gain. */
/// # Safety
///
/// `out` must be valid for writes up to `safe`, and `from` for reads of the bytes that are
/// copied, which may be bytes that this copy writes.
#[cfg_attr(target_arch = "aarch64", inline(always))]
#[cfg_attr(not(target_arch = "aarch64"), inline)]
pub(crate) unsafe fn chunkcopy_safe(
    mut out: *mut u8,
    mut from: *const u8,
    mut len: usize,
    safe: *mut u8,
) -> *mut u8 {
    // SAFETY: the caller guarantees the ranges. The copies below never take more bytes at once
    // than lie between the two pointers, so no single copy overlaps itself.
    unsafe {
        let safelen = safe.offset_from_unsigned(out);
        len = len.min(safelen);
        let olap_src = from >= out.cast_const() && from < out.add(len).cast_const();
        let olap_dst = out.cast_const() >= from && out.cast_const() < from.add(len);

        /* For all cases without overlap, memcpy is ideal */
        if !(olap_src || olap_dst) {
            ptr::copy_nonoverlapping(from, out, len);
            return out.add(len);
        }

        /* Complete overlap: Source == destination */
        if out.cast_const() == from {
            return out.add(len);
        }

        /* We are emulating a self-modifying copy loop here. To do this in a way that doesn't produce undefined behavior,
         * we have to get a bit clever. First if the overlap is such that src falls between dst and dst+len, we can do the
         * initial bulk memcpy of the nonoverlapping region. Then, we can leverage the size of this to determine the safest
         * atomic memcpy size we can pick such that we have non-overlapping regions. This effectively becomes a safe look
         * behind or lookahead distance. */
        let non_olap_size = from.addr().abs_diff(out.addr());

        /* So this doesn't give use a worst case scenario of function calls in a loop,
         * we want to instead break this down into copy blocks of fixed lengths
         *
         * TODO: The memcpy calls aren't inlined on architectures with strict memory alignment
         */
        while len != 0 {
            let mut tocopy = non_olap_size.min(len);
            len -= tocopy;

            while tocopy >= 16 {
                ptr::copy_nonoverlapping(from, out, 16);
                out = out.add(16);
                from = from.add(16);
                tocopy -= 16;
            }

            if tocopy >= 8 {
                ptr::copy_nonoverlapping(from, out, 8);
                out = out.add(8);
                from = from.add(8);
                tocopy -= 8;
            }

            if tocopy >= 4 {
                ptr::copy_nonoverlapping(from, out, 4);
                out = out.add(4);
                from = from.add(4);
                tocopy -= 4;
            }

            // Less than 4 bytes are left. C copies them in a byte loop, which the compiler turns
            // into a guarded vector loop that costs a taken branch for every byte of a run.
            if tocopy & 2 != 0 {
                ptr::copy_nonoverlapping(from, out, 2);
                out = out.add(2);
                from = from.add(2);
            }
            if tocopy & 1 != 0 {
                *out = *from;
                out = out.add(1);
                from = from.add(1);
            }
        }

        out
    }
}
