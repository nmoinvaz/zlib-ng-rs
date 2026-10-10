//! adler32.c -- compute the Adler-32 checksum of a data stream
//! Copyright (C) 1995-2011, 2016 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

// The checksum and offset types are aliases whose widths depend on the build.
#![allow(clippy::unnecessary_cast, clippy::useless_conversion)]

#[cfg(feature = "zlib-compat")]
use core::ffi::c_ulong;

use crate::adler32_p::BASE;
use crate::functable::functable_adler32;
use crate::zbuild::{prefix, z_checksum_t};
#[cfg(feature = "zlib-compat")]
use crate::zconf::z_off_t;
use crate::zconf::z_off64_t;
use crate::zutil::ADLER32_INITIAL_VALUE;

/// # Safety
///
/// `buf` must be null or valid for reads of `len` bytes.
#[unsafe(export_name = prefix!("adler32_z"))]
pub unsafe extern "C" fn adler32_z(
    adler: z_checksum_t,
    buf: *const u8,
    len: usize,
) -> z_checksum_t {
    if buf.is_null() {
        return z_checksum_t::from(ADLER32_INITIAL_VALUE);
    }
    // SAFETY: the caller guarantees buf is valid for reads of len bytes.
    z_checksum_t::from(unsafe { functable_adler32(adler as u32, buf, len) })
}

/* ========================================================================= */
/// # Safety
///
/// `buf` must be null or valid for reads of `len` bytes.
#[unsafe(export_name = prefix!("adler32"))]
pub unsafe extern "C" fn adler32(adler: z_checksum_t, buf: *const u8, len: u32) -> z_checksum_t {
    if buf.is_null() {
        return z_checksum_t::from(ADLER32_INITIAL_VALUE);
    }
    // SAFETY: the caller guarantees buf is valid for reads of len bytes.
    z_checksum_t::from(unsafe { functable_adler32(adler as u32, buf, len as usize) })
}

/* ========================================================================= */
fn adler32_combine_(adler1: u32, adler2: u32, len2: i64) -> u32 {
    /* for negative len, return invalid adler32 as a clue for debugging */
    if len2 < 0 {
        return 0xffffffff;
    }

    /* the derivation of this formula is left as an exercise for the reader */
    let rem = (len2 % i64::from(BASE)) as u32; /* assumes len2 >= 0 */
    let mut sum1 = adler1 & 0xffff;
    let mut sum2 = rem * sum1;
    sum2 %= BASE;
    sum1 += (adler2 & 0xffff) + BASE - 1;
    sum2 += ((adler1 >> 16) & 0xffff) + ((adler2 >> 16) & 0xffff) + BASE - rem;
    if sum1 >= BASE {
        sum1 -= BASE;
    }
    if sum1 >= BASE {
        sum1 -= BASE;
    }
    if sum2 >= (BASE << 1) {
        sum2 -= BASE << 1;
    }
    if sum2 >= BASE {
        sum2 -= BASE;
    }
    sum1 | (sum2 << 16)
}

/* ========================================================================= */
#[cfg(feature = "zlib-compat")]
#[unsafe(export_name = "adler32_combine")]
pub extern "C" fn adler32_combine(adler1: c_ulong, adler2: c_ulong, len2: z_off_t) -> c_ulong {
    c_ulong::from(adler32_combine_(
        adler1 as u32,
        adler2 as u32,
        i64::from(len2),
    ))
}

#[cfg_attr(feature = "zlib-compat", unsafe(export_name = "adler32_combine64"))]
#[cfg_attr(
    not(feature = "zlib-compat"),
    unsafe(export_name = "zng_adler32_combine")
)]
pub extern "C" fn adler32_combine64(
    adler1: z_checksum_t,
    adler2: z_checksum_t,
    len2: z_off64_t,
) -> z_checksum_t {
    z_checksum_t::from(adler32_combine_(
        adler1 as u32,
        adler2 as u32,
        i64::from(len2),
    ))
}
