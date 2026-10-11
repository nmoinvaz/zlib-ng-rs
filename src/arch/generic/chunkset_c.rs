//! chunkset.c -- inline functions to copy small data chunks.
//! For conditions of distribution and use, see copyright notice in zlib.h

use crate::chunkset_tpl::{Chunk, chunkmemset_safe};
use crate::inffast_tpl::inflate_fast;
use crate::zlib::z_stream;
use crate::zmemory::{zng_memread_4, zng_memread_8, zng_memwrite_8};

/// The generic chunk is a 64-bit integer.
impl Chunk for u64 {
    const HAVE_CHUNKMEMSET_1: bool = false;

    #[inline(always)]
    unsafe fn chunkmemset(from: *const u8, dist: usize) -> Option<Self> {
        // SAFETY: the caller guarantees dist bytes at from.
        unsafe {
            match dist {
                4 => {
                    let tmp = u64::from(zng_memread_4(from));
                    Some(tmp | (tmp << 32))
                }
                8 => Some(zng_memread_8(from)),
                _ => None,
            }
        }
    }

    #[inline(always)]
    unsafe fn loadchunk(s: *const u8) -> Self {
        // SAFETY: the caller guarantees one chunk at s.
        unsafe { zng_memread_8(s) }
    }

    #[inline(always)]
    unsafe fn storechunk(out: *mut u8, chunk: Self) {
        // SAFETY: the caller guarantees room for one chunk at out.
        unsafe { zng_memwrite_8(out, chunk) }
    }
}

/// # Safety
///
/// `out` must be valid for writes of `left` bytes, and `from` for reads of the bytes that are
/// copied, which may be bytes that this copy writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chunkmemset_safe_c(
    out: *mut u8,
    from: *mut u8,
    len: usize,
    left: usize,
) -> *mut u8 {
    // SAFETY: the caller upholds the contract of chunkmemset_safe.
    unsafe { chunkmemset_safe::<u64>(out, from, len, left) }
}

/// # Safety
///
/// `strm` must be a valid inflate stream that upholds the entry assumptions of inflate_fast.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inflate_fast_c(strm: *mut z_stream, start: u32) {
    // SAFETY: the caller upholds the contract of inflate_fast.
    unsafe { inflate_fast::<u64, false>(strm, start) }
}

/// # Safety
///
/// `strm` must be a valid inflate stream that upholds the entry assumptions of inflate_fast in
/// its safe mode.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inflate_fast_safe_c(strm: *mut z_stream, start: u32) {
    // SAFETY: the caller upholds the contract of inflate_fast.
    unsafe { inflate_fast::<u64, true>(strm, start) }
}
