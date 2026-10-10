//! zlib-ng.h -- interface of the 'zlib-ng' compression library, forked from zlib.
//!
//! Copyright (C) 1995-2026 Jean-loup Gailly and Mark Adler
//!
//! This software is provided 'as-is', without any express or implied
//! warranty.  In no event will the authors be held liable for any damages
//! arising from the use of this software.
//!
//! Permission is granted to anyone to use this software for any purpose,
//! including commercial applications, and to alter it and redistribute it
//! freely, subject to the following restrictions:
//!
//! 1. The origin of this software must not be misrepresented; you must not
//!    claim that you wrote the original software. If you use this software
//!    in a product, an acknowledgment in the product documentation would be
//!    appreciated but is not required.
//! 2. Altered source versions must be plainly marked as such, and must not be
//!    misrepresented as being the original software.
//! 3. This notice may not be removed or altered from any source distribution.
//!
//! Jean-loup Gailly        Mark Adler
//! jloup@gzip.org          madler@alumni.caltech.edu
//!
//! The data format used by the zlib library is described by RFCs (Request for
//! Comments) 1950 to 1952 at <https://datatracker.ietf.org/doc/html/rfc1950>
//! (zlib format), rfc1951 (deflate format) and rfc1952 (gzip format).

#![allow(non_camel_case_types)]

#[cfg(feature = "zlib-compat")]
use core::ffi::CStr;
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

use crate::zbuild::z_uintmax_t;

#[cfg(feature = "zlib-compat")]
pub const ZLIB_VERSION: &CStr = c"1.3.2.zlib-ng";

pub type alloc_func =
    Option<unsafe extern "C" fn(opaque: *mut c_void, items: c_uint, size: c_uint) -> *mut c_void>;
pub type free_func = Option<unsafe extern "C" fn(opaque: *mut c_void, address: *mut c_void)>;

/// not visible by applications
#[repr(C)]
pub struct internal_state {
    _private: [u8; 0],
}

#[repr(C)]
pub struct z_stream {
    /// next input byte
    pub next_in: *const u8,
    /// number of bytes available at next_in
    pub avail_in: u32,
    /// total number of input bytes read so far
    pub total_in: z_uintmax_t,

    /// next output byte will go here
    pub next_out: *mut u8,
    /// remaining free space at next_out
    pub avail_out: u32,
    /// total number of bytes output so far
    pub total_out: z_uintmax_t,

    /// last error message, NULL if no error
    pub msg: *const c_char,
    /// not visible by applications
    pub state: *mut internal_state,

    /// used to allocate the internal state
    pub zalloc: alloc_func,
    /// used to free the internal state
    pub zfree: free_func,
    /// private data object passed to zalloc and zfree
    pub opaque: *mut c_void,

    /// best guess about the data type: binary or text
    /// for deflate, or the decoding state for inflate
    pub data_type: c_int,
    /// Adler-32 or CRC-32 value of the uncompressed data
    #[cfg(feature = "zlib-compat")]
    pub adler: c_ulong,
    /// Adler-32 or CRC-32 value of the uncompressed data
    #[cfg(not(feature = "zlib-compat"))]
    pub adler: u32,
    /// reserved for future use
    pub reserved: c_ulong,
}

/* constants */

pub const Z_NO_FLUSH: i32 = 0;
pub const Z_PARTIAL_FLUSH: i32 = 1;
pub const Z_SYNC_FLUSH: i32 = 2;
pub const Z_FULL_FLUSH: i32 = 3;
pub const Z_FINISH: i32 = 4;
pub const Z_BLOCK: i32 = 5;
pub const Z_TREES: i32 = 6;
/* Allowed flush values; see deflate() and inflate() below for details */

pub const Z_OK: i32 = 0;
pub const Z_STREAM_END: i32 = 1;
pub const Z_NEED_DICT: i32 = 2;
pub const Z_ERRNO: i32 = -1;
pub const Z_STREAM_ERROR: i32 = -2;
pub const Z_DATA_ERROR: i32 = -3;
pub const Z_MEM_ERROR: i32 = -4;
pub const Z_BUF_ERROR: i32 = -5;
pub const Z_VERSION_ERROR: i32 = -6;
/* Return codes for the compression/decompression functions. Negative values
 * are errors, positive values are used for special but normal events.
 */
