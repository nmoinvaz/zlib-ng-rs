//! zutil.h -- internal interface and configuration of the compression library
//! Copyright (C) 1995-2026 Jean-loup Gailly, Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

/* WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change. Applications should only use zlib.h.
*/

#![cfg_attr(feature = "no-quick-strategy", allow(dead_code))]

/// initial adler-32 hash value
pub(crate) const ADLER32_INITIAL_VALUE: u32 = 1;
/// initial crc-32 hash value
pub(crate) const CRC32_INITIAL_VALUE: u32 = 0;

/// The minimum match length mandated by the deflate standard
pub(crate) const STD_MIN_MATCH: usize = 3;
/// The maximum match length mandated by the deflate standard
pub(crate) const STD_MAX_MATCH: usize = 258;

/// The minimum wanted match length, affects deflate_quick, deflate_fast, deflate_medium and deflate_slow
pub(crate) const WANT_MIN_MATCH: usize = 4;

/// zlib format overhead
pub(crate) const ZLIB_WRAPLEN: usize = 6;

pub(crate) const DEFLATE_HEADER_BITS: usize = 3;
pub(crate) const DEFLATE_EOBS_BITS: usize = 15;
pub(crate) const DEFLATE_PAD_BITS: usize = 6;
/// deflate block overhead: 3 bits for block start + 15 bits for block end + padding to nearest byte
pub(crate) const DEFLATE_BLOCK_OVERHEAD: usize =
    (DEFLATE_HEADER_BITS + DEFLATE_EOBS_BITS + DEFLATE_PAD_BITS) >> 3;

pub(crate) const DEFLATE_QUICK_LIT_MAX_BITS: usize = 9;
/// deflate_quick worst-case overhead: 9 bits per literal, round up to next byte (+7)
#[inline(always)]
pub(crate) const fn deflate_quick_overhead(x: usize) -> usize {
    x.wrapping_mul(DEFLATE_QUICK_LIT_MAX_BITS - 8)
        .wrapping_add(7)
        >> 3
}
