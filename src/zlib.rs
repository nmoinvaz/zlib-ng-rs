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

use core::ffi::CStr;
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

use crate::zbuild::{z_checksum_t, z_uintmax_t};

#[cfg(feature = "zlib-compat")]
pub const ZLIB_VERSION: &CStr = c"1.3.2.zlib-ng";
#[cfg(not(feature = "zlib-compat"))]
pub const ZLIBNG_VERSION: &CStr = c"2.3.90";

pub type alloc_func =
    Option<unsafe extern "C" fn(opaque: *mut c_void, items: c_uint, size: c_uint) -> *mut c_void>;
pub type free_func = Option<unsafe extern "C" fn(opaque: *mut c_void, address: *mut c_void)>;

/// gzip header information passed to and from zlib routines.  See RFC 1952
/// for more details on the meanings of these fields.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct gz_header {
    /// true if compressed data believed to be text
    pub text: i32,
    /// modification time
    pub time: c_ulong,
    /// extra flags (not used when writing a gzip file)
    pub xflags: i32,
    /// operating system
    pub os: i32,
    /// pointer to extra field or NULL if none
    pub extra: *mut u8,
    /// extra field length (valid if extra != NULL)
    pub extra_len: u32,
    /// space at extra (only when reading header)
    pub extra_max: u32,
    /// pointer to zero-terminated file name or NULL
    pub name: *mut u8,
    /// space at name (only when reading header)
    pub name_max: u32,
    /// pointer to zero-terminated comment or NULL
    pub comment: *mut u8,
    /// space at comment (only when reading header)
    pub comm_max: u32,
    /// true if there was or will be a header crc
    pub hcrc: i32,
    /// true when done reading gzip header (not used when writing a gzip file)
    pub done: i32,
}

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
    pub adler: z_checksum_t,
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

pub const Z_NO_COMPRESSION: i32 = 0;
pub const Z_BEST_SPEED: i32 = 1;
pub const Z_BEST_COMPRESSION: i32 = 9;
pub const Z_DEFAULT_COMPRESSION: i32 = -1;
/* compression levels */

pub const Z_FILTERED: i32 = 1;
pub const Z_HUFFMAN_ONLY: i32 = 2;
pub const Z_RLE: i32 = 3;
pub const Z_FIXED: i32 = 4;
pub const Z_DEFAULT_STRATEGY: i32 = 0;
/* compression strategy; see deflateInit2() below for details */

/// The deflate compression method (the only one supported in this version)
pub const Z_DEFLATED: i32 = 8;

pub const Z_BINARY: i32 = 0;
pub const Z_TEXT: i32 = 1;
/// for compatibility with 1.2.2 and earlier
pub const Z_ASCII: i32 = Z_TEXT;
pub const Z_UNKNOWN: i32 = 2;
/* Possible values of the data_type field for deflate() */

/// compression level, represented as an int
#[cfg(not(feature = "zlib-compat"))]
pub const Z_DEFLATE_LEVEL: c_int = 0;
/// compression strategy, represented as an int
#[cfg(not(feature = "zlib-compat"))]
pub const Z_DEFLATE_STRATEGY: c_int = 1;
/// whether reproducible compression results are required, represented as an int
#[cfg(not(feature = "zlib-compat"))]
pub const Z_DEFLATE_REPRODUCIBLE: c_int = 2;

#[cfg(not(feature = "zlib-compat"))]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct zng_deflate_param_value {
    /// parameter ID
    pub param: c_int,
    /// parameter value
    pub buf: *mut c_void,
    /// parameter value size
    pub size: usize,
    /// result of the last set/get call
    pub status: i32,
}
