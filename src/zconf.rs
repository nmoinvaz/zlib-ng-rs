//! zconf-ng.h -- configuration of the zlib-ng compression library
//! Copyright (C) 1995-2026 Jean-loup Gailly, Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

#![allow(non_camel_case_types)]

/// Maximum value for memLevel in deflateInit2
pub const MAX_MEM_LEVEL: i32 = 9;

/* Maximum value for windowBits in deflateInit2 and inflateInit2.
 * WARNING: reducing MAX_WBITS makes minigzip unable to extract .gz files
 * created by gzip. (Files created by minigzip can still be extracted by
 * gzip.)
 */
/// 256 LZ77 window
pub const MIN_WBITS: i32 = 8;
/// 32K LZ77 window
pub const MAX_WBITS: i32 = 15;

// The build measures both offset types from the generated C header.
#[cfg(feature = "z-off-t-32")]
pub type z_off_t = i32;
#[cfg(not(feature = "z-off-t-32"))]
pub type z_off_t = i64;

#[cfg(feature = "z-off64-t-32")]
pub type z_off64_t = i32;
#[cfg(not(feature = "z-off64-t-32"))]
pub type z_off64_t = i64;
