//! adler32.c -- compute the Adler-32 checksum of a data stream
//! Copyright (C) 1995-2011, 2016 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::{ptr, slice};

use crate::adler32_p::{
    BASE, NMAX_ALIGNED8, adler32_copy_align, adler32_copy_tail, adler32_swar_words,
};
use crate::zbuild::{align_diff, align_down};

pub(crate) fn adler32(adler: u32, buf: &[u8]) -> u32 {
    /* split Adler-32 into component sums */
    let mut sum2 = (adler >> 16) & 0xffff;
    let mut adler = adler & 0xffff;

    /* in case user likes doing a byte at a time, keep it fast */
    if buf.len() == 1 {
        return adler32_copy_tail(adler, buf, sum2, true);
    }

    /* in case short lengths are provided, keep it somewhat fast */
    if buf.len() < 16 {
        return adler32_copy_tail(adler, buf, sum2, true);
    }

    /* Align source to 8 bytes so SWAR loads are naturally aligned */
    let (head, mut buf) = buf.split_at(align_diff(buf.as_ptr(), 8));
    let mut nmax = NMAX_ALIGNED8;
    if !head.is_empty() {
        adler32_copy_align(&mut adler, head, &mut sum2);
        nmax = align_down(nmax - head.len(), 8);
    }

    /* do length NMAX blocks -- requires just one modulo operation */
    while let Some((block, rest)) = buf.split_at_checked(nmax) {
        adler32_swar_words(&mut adler, block, &mut sum2);
        buf = rest;

        adler %= BASE;
        sum2 %= BASE;
        nmax = NMAX_ALIGNED8;
    }

    /* do remaining bytes (less than NMAX, still just one modulo) */
    adler32_copy_tail(adler, buf, sum2, !buf.is_empty())
}

/// # Safety
///
/// `buf` must be valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adler32_c(adler: u32, buf: *const u8, len: usize) -> u32 {
    if len == 0 {
        return adler32(adler, &[]);
    }
    // SAFETY: the caller guarantees buf is valid for reads of len bytes.
    adler32(adler, unsafe { slice::from_raw_parts(buf, len) })
}

/// # Safety
///
/// `src` must be valid for reads of `len` bytes, `dst` must be valid for writes of `len` bytes,
/// and the two must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn adler32_copy_c(
    adler: u32,
    dst: *mut u8,
    src: *const u8,
    len: usize,
) -> u32 {
    // SAFETY: the caller guarantees src is valid for reads of len bytes.
    let adler = unsafe { adler32_c(adler, src, len) };
    if len != 0 {
        // SAFETY: the caller guarantees both ranges are valid and do not overlap.
        unsafe { ptr::copy_nonoverlapping(src, dst, len) };
    }
    adler
}
