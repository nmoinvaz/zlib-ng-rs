//! chunkset_tpl.h -- inline functions to copy small data chunks.
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! The C template takes its chunk type from macros. Here a trait supplies it, with the hooks that
//! the chunk types built from Rust use. The half chunk and masked variants of the vector chunk
//! types stay in the C template.

use core::mem::MaybeUninit;
use core::ptr;

use crate::zbuild::{OPTIMAL_CMP, unlikely};

/// One chunk of bytes, chunk_t in C
pub(crate) trait Chunk: Copy {
    /// Whether chunkmemset handles a distance of one, HAVE_CHUNKMEMSET_1 in C
    const HAVE_CHUNKMEMSET_1: bool;

    /// The chunk filled with the `dist` bytes at `from`, for the distances that have a direct
    /// way to do that, HAVE_CHUNKMEMSET_2 to HAVE_CHUNKMEMSET_16 in C
    ///
    /// # Safety
    ///
    /// `from` must be valid for reads of `dist` bytes.
    unsafe fn chunkmemset(from: *const u8, dist: usize) -> Option<Self>;

    /// # Safety
    ///
    /// `s` must be valid for reads of one chunk.
    unsafe fn loadchunk(s: *const u8) -> Self;

    /// # Safety
    ///
    /// `out` must be valid for writes of one chunk.
    unsafe fn storechunk(out: *mut u8, chunk: Self);
}

/* Returns the chunk size */
#[inline(always)]
pub(crate) const fn chunksize<C: Chunk>() -> usize {
    size_of::<C>()
}

/* Behave like memcpy, but assume that it's OK to overwrite at least
chunk_t bytes of output even if the length is shorter than this,
that the length is non-zero, and that `from` lags `out` by at least
sizeof chunk_t bytes (or that they don't overlap at all or simply that
the distance is less than the length of the copy).

Aside from better memory bus utilization, this means that short copies
(chunk_t bytes or fewer) will fall straight through the loop
without iteration, which will hopefully make the branch prediction more
reliable. */
/// # Safety
///
/// `len` must not be zero. `from` must be valid for reads and `out` for writes of `len` bytes
/// rounded up to whole chunks.
#[inline]
pub(crate) unsafe fn chunkcopy<C: Chunk>(
    mut out: *mut u8,
    mut from: *const u8,
    mut len: usize,
) -> *mut u8 {
    debug_assert!(len > 0, "chunkcopy should never have a length 0");
    // SAFETY: the caller guarantees room for whole chunks at both pointers.
    unsafe {
        let align = ((len - 1) % size_of::<C>()) + 1;
        C::storechunk(out, C::loadchunk(from));
        out = out.add(align);
        from = from.add(align);
        len -= align;
        while len > 0 {
            C::storechunk(out, C::loadchunk(from));
            out = out.add(size_of::<C>());
            from = from.add(size_of::<C>());
            len -= size_of::<C>();
        }
        out
    }
}

/* Perform short copies until distance can be rewritten as being at least
sizeof chunk_t.

This assumes that it's OK to overwrite at least the first
2*sizeof(chunk_t) bytes of output even if the copy is shorter than this.
This assumption holds because inflate_fast() starts every iteration with at
least 258 bytes of output space available (258 being the maximum length
output from a single token; see inflate_fast()'s assumptions below). */
/// # Safety
///
/// `out` must be valid for writes of two chunks, and the `dist` bytes ahead of it for reads.
#[inline]
pub(crate) unsafe fn chunkunroll<C: Chunk>(
    mut out: *mut u8,
    dist: &mut u32,
    len: &mut u32,
) -> *mut u8 {
    // SAFETY: the caller guarantees the bytes ahead of out and room for two chunks behind it.
    unsafe {
        let from = out.sub(*dist as usize).cast_const();
        while *dist < *len && (*dist as usize) < size_of::<C>() {
            C::storechunk(out, C::loadchunk(from));
            out = out.add(*dist as usize);
            *len -= *dist;
            *dist += *dist;
        }
        out
    }
}

/* Loads a magazine to feed into memory of the pattern */
/// # Safety
///
/// `buf` must be valid for reads of `dist` bytes, and `dist` must not be zero.
#[inline]
unsafe fn get_chunk_mag<C: Chunk>(buf: *const u8, chunk_rem: &mut usize, dist: usize) -> C {
    /* This code takes string of length dist from "from" and repeats
     * it for as many times as can fit in a chunk_t (vector register) */
    let mut bytes_remaining = size_of::<C>();
    let mut chunk_load = MaybeUninit::<C>::uninit();
    let mut cur_chunk = chunk_load.as_mut_ptr().cast::<u8>();
    // SAFETY: the caller guarantees dist bytes at buf, and the copies fill the chunk exactly.
    unsafe {
        while bytes_remaining != 0 {
            let cpy_dist = dist.min(bytes_remaining);
            ptr::copy_nonoverlapping(buf, cur_chunk, cpy_dist);
            bytes_remaining -= cpy_dist;
            cur_chunk = cur_chunk.add(cpy_dist);
            /* This allows us to bypass an expensive integer division since we're effectively
             * counting in this loop, anyway */
            *chunk_rem = cpy_dist;
        }

        chunk_load.assume_init()
    }
}

/* Copy DIST bytes from OUT - DIST into OUT + DIST * k, for 0 <= k < LEN/DIST.
Return OUT + LEN. */
/// # Safety
///
/// `from` and `out` must differ. `from` must be valid for reads and `out` for writes of `len`
/// bytes rounded up to whole chunks.
#[inline]
pub(crate) unsafe fn chunkmemset<C: Chunk>(
    mut out: *mut u8,
    from: *const u8,
    mut len: usize,
) -> *mut u8 {
    /* Debug performance related issues when len < sizeof(uint64_t):
    Assert(len >= sizeof(uint64_t), "chunkmemset should be called on larger chunks"); */
    debug_assert!(
        from != out.cast_const(),
        "chunkmemset cannot have a distance 0"
    );

    let mut chunk_mod = 0;
    let dist = out.addr().abs_diff(from.addr());

    // SAFETY: the caller guarantees room for whole chunks at both pointers.
    unsafe {
        /* We are supporting the case for when we are reading bytes from ahead in the buffer.
         * We now have to handle this, though it wasn't _quite_ clear if this rare circumstance
         * always needed to be handled here or if we're just now seeing it because we are
         * dispatching to this function, more */
        if out.cast_const() < from && dist < len {
            /* Here the memmove semantics match perfectly, as when this happens we are
             * effectively sliding down the contents of memory by dist bytes */
            ptr::copy(from, out, len);
            return out.add(len);
        }

        if !C::HAVE_CHUNKMEMSET_1 && dist == 1 {
            ptr::write_bytes(out, *from, len);
            return out.add(len);
        } else if dist >= len || dist >= size_of::<C>() {
            return chunkcopy::<C>(out, from, len);
        }

        let chunk_load = match C::chunkmemset(from, dist) {
            Some(chunk) => chunk,
            None => get_chunk_mag::<C>(from, &mut chunk_mod, dist),
        };

        if len <= size_of::<C>() {
            C::storechunk(out, chunk_load);
            return out.add(len);
        }

        let adv_amount = size_of::<C>() - chunk_mod;

        while len >= 2 * size_of::<C>() {
            C::storechunk(out, chunk_load);
            C::storechunk(out.add(adv_amount), chunk_load);
            out = out.add(2 * adv_amount);
            len -= 2 * adv_amount;
        }

        /* If we don't have a "dist" length that divides evenly into a vector
         * register, we can write the whole vector register but we need only
         * advance by the amount of the whole string that fits in our chunk_t.
         * If we do divide evenly into the vector length, adv_amount = chunk_t size*/
        while len >= size_of::<C>() {
            C::storechunk(out, chunk_load);
            len -= adv_amount;
            out = out.add(adv_amount);
        }

        if len != 0 {
            // Fewer bytes than one chunk remain, so only the pieces that fit in a chunk can be set.
            let mut chunk_p = (&raw const chunk_load).cast::<u8>();
            if size_of::<C>() > 16 && len & 16 != 0 {
                ptr::copy_nonoverlapping(chunk_p, out, 16);
                out = out.add(16);
                chunk_p = chunk_p.add(16);
            }
            if size_of::<C>() > 8 && len & 8 != 0 {
                ptr::copy_nonoverlapping(chunk_p, out, 8);
                out = out.add(8);
                chunk_p = chunk_p.add(8);
            }
            if len & 4 != 0 {
                ptr::copy_nonoverlapping(chunk_p, out, 4);
                out = out.add(4);
                chunk_p = chunk_p.add(4);
            }
            if len & 2 != 0 {
                ptr::copy_nonoverlapping(chunk_p, out, 2);
                out = out.add(2);
                chunk_p = chunk_p.add(2);
            }
            if len & 1 != 0 {
                *out = *chunk_p;
                out = out.add(1);
            }
        }

        out
    }
}

/// # Safety
///
/// `out` must be valid for writes of `left` bytes, and `from` for reads of the bytes that are
/// copied, which may be bytes that this copy writes.
#[inline(always)]
pub(crate) unsafe fn chunkmemset_safe<C: Chunk>(
    mut out: *mut u8,
    mut from: *const u8,
    mut len: usize,
    mut left: usize,
) -> *mut u8 {
    len = len.min(left);

    // SAFETY: the caller guarantees left bytes at out, and len is at most that. A chunk is only
    // written when a whole one fits in what is left.
    unsafe {
        if OPTIMAL_CMP < 64 {
            let align_mask = if OPTIMAL_CMP < 32 { 7 } else { 3 };
            while (out.addr() & align_mask) != 0 && len > 0 {
                *out = *from;
                out = out.add(1);
                from = from.add(1);
                len -= 1;
                left -= 1;
            }
        }

        if unlikely(left < size_of::<C>()) {
            while len > 0 {
                *out = *from;
                out = out.add(1);
                from = from.add(1);
                len -= 1;
            }

            return out;
        }

        if len != 0 {
            out = chunkmemset::<C>(out, from, len);
        }

        out
    }
}

/// # Safety
///
/// `out` must be valid for writes up to `safe`, and `from` for reads of the bytes that are
/// copied, which may be bytes that this copy writes.
#[inline]
pub(crate) unsafe fn chunkcopy_safe<C: Chunk>(
    mut out: *mut u8,
    mut from: *const u8,
    mut len: usize,
    safe: *mut u8,
) -> *mut u8 {
    // SAFETY: the caller guarantees the ranges. A chunk is only written when a whole one fits
    // ahead of safe at both pointers.
    unsafe {
        if out.cast_const() == from {
            return out.add(len);
        }

        let safelen = safe.offset_from_unsigned(out);
        len = len.min(safelen);

        let from_dist = safe.addr().abs_diff(from.addr());
        if unlikely(from_dist < size_of::<C>() || safelen < size_of::<C>()) {
            while len != 0 {
                *out = *from;
                out = out.add(1);
                from = from.add(1);
                len -= 1;
            }

            return out;
        }

        chunkmemset::<C>(out, from, len)
    }
}
