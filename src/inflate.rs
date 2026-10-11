//! inflate.h -- internal inflate state definition
//! Copyright (C) 1995-2019 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! inflate.c is still built from C, so this also declares the functions of it that the Rust
//! sources call.

/* WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change. Applications should only use zlib.h.
*/

#![allow(non_camel_case_types)]
// Only the build with the C sources checks every mode against them.
#![cfg_attr(not(feature = "c-layout"), allow(dead_code))]

#[cfg(feature = "zlib-compat")]
use core::ffi::c_char;
use core::ffi::{c_int, c_uint, c_ulong};

use crate::inftrees::{ENOUGH, code};
use crate::zbuild::prefix;
#[cfg(feature = "zlib-compat")]
use crate::zlib::ZLIB_VERSION;
use crate::zlib::{free_func, gz_header, z_stream};

/// Possible inflate modes between inflate() calls. The C sources store them in the state, so
/// this is a plain integer that can hold any value they write.
pub(crate) type inflate_mode = c_uint;

/// i: waiting for magic header
pub(crate) const HEAD: inflate_mode = 16180;
/// i: waiting for method and flags (gzip)
pub(crate) const FLAGS: inflate_mode = 16181;
/// i: waiting for modification time (gzip)
pub(crate) const TIME: inflate_mode = 16182;
/// i: waiting for extra flags and operating system (gzip)
pub(crate) const OS: inflate_mode = 16183;
/// i: waiting for extra length (gzip)
pub(crate) const EXLEN: inflate_mode = 16184;
/// i: waiting for extra bytes (gzip)
pub(crate) const EXTRA: inflate_mode = 16185;
/// i: waiting for end of file name (gzip)
pub(crate) const NAME: inflate_mode = 16186;
/// i: waiting for end of comment (gzip)
pub(crate) const COMMENT: inflate_mode = 16187;
/// i: waiting for header crc (gzip)
pub(crate) const HCRC: inflate_mode = 16188;
/// i: waiting for dictionary check value
pub(crate) const DICTID: inflate_mode = 16189;
/// waiting for inflateSetDictionary() call
pub(crate) const DICT: inflate_mode = 16190;
/// i: waiting for type bits, including last-flag bit
pub(crate) const TYPE: inflate_mode = 16191;
/// i: same, but skip check to exit inflate on new block
pub(crate) const TYPEDO: inflate_mode = 16192;
/// i: waiting for stored size (length and complement)
pub(crate) const STORED: inflate_mode = 16193;
/// i/o: same as COPY below, but only first time in
pub(crate) const COPY_: inflate_mode = 16194;
/// i/o: waiting for input or output to copy stored block
pub(crate) const COPY: inflate_mode = 16195;
/// i: waiting for dynamic block table lengths
pub(crate) const TABLE: inflate_mode = 16196;
/// i: waiting for code length code lengths
pub(crate) const LENLENS: inflate_mode = 16197;
/// i: waiting for length/lit and distance code lengths
pub(crate) const CODELENS: inflate_mode = 16198;
/// i: same as LEN below, but only first time in
pub(crate) const LEN_: inflate_mode = 16199;
/// i: waiting for length/lit/eob code
pub(crate) const LEN: inflate_mode = 16200;
/// i: waiting for length extra bits
pub(crate) const LENEXT: inflate_mode = 16201;
/// i: waiting for distance code
pub(crate) const DIST: inflate_mode = 16202;
/// i: waiting for distance extra bits
pub(crate) const DISTEXT: inflate_mode = 16203;
/// o: waiting for output space to copy string
pub(crate) const MATCH: inflate_mode = 16204;
/// o: waiting for output space to write literal
pub(crate) const LIT: inflate_mode = 16205;
/// i: waiting for 32-bit check value
pub(crate) const CHECK: inflate_mode = 16206;
/// i: waiting for 32-bit length (gzip)
pub(crate) const LENGTH: inflate_mode = 16207;
/// finished check, done -- remain here until reset
pub(crate) const DONE: inflate_mode = 16208;
/// got a data error -- remain here until reset
pub(crate) const BAD: inflate_mode = 16209;
/// looking for synchronization bytes to restart inflate()
pub(crate) const SYNC: inflate_mode = 16210;

/*
   State transitions between above modes -

   (most modes can go to BAD on error -- not shown for clarity)

   Process header:
       HEAD -> (gzip) or (zlib) or (raw)
       (gzip) -> FLAGS -> TIME -> OS -> EXLEN -> EXTRA -> NAME -> COMMENT ->
                 HCRC -> TYPE
       (zlib) -> DICTID or TYPE
       DICTID -> DICT -> TYPE
       (raw) -> TYPEDO
   Read deflate blocks:
           TYPE -> TYPEDO -> STORED or TABLE or LEN_ or CHECK
           STORED -> COPY_ -> COPY -> TYPE
           TABLE -> LENLENS -> CODELENS -> LEN_
           LEN_ -> LEN
   Read deflate codes in fixed or dynamic block:
               LEN -> LENEXT or LIT or TYPE
               LENEXT -> DIST -> DISTEXT -> MATCH -> LEN
               LIT -> LEN
   Process trailer:
       CHECK -> LENGTH -> DONE
*/

/// Struct for memory allocation handling
#[repr(C)]
pub(crate) struct inflate_allocs {
    pub(crate) buf_start: *mut u8,
    pub(crate) zfree: free_func,
    pub(crate) state: *mut inflate_state,
    pub(crate) window: *mut u8,
}

/// State maintained between inflate() calls -- approximately 7K bytes, not
/// including the allocated sliding window, which is up to 32K bytes.
///
/// The C sources own the structure and end it with fields that depend on the architecture. This
/// mirrors the fields ahead of those, and the build checks every offset against C.
#[repr(C)]
pub(crate) struct inflate_state {
    /// pointer back to this zlib stream
    pub(crate) strm: *mut z_stream,
    /// current inflate mode
    pub(crate) mode: inflate_mode,
    /// true if processing last block
    pub(crate) last: c_int,
    /// bit 0 true for zlib, bit 1 true for gzip, bit 2 true to validate check value
    pub(crate) wrap: c_int,
    /// true if dictionary provided
    pub(crate) havedict: c_int,
    /// gzip header method and flags, 0 if zlib, or -1 if raw or no header yet
    pub(crate) flags: c_int,
    /// initial length of match, for inflateMark
    pub(crate) was: c_uint,
    /// protected copy of check value
    pub(crate) check: c_ulong,
    /// protected copy of output count
    pub(crate) total: c_ulong,
    /// where to save gzip header information
    pub(crate) head: *mut gz_header,
    /// bits back of last unprocessed length/lit
    pub(crate) back: c_int,

    /* sliding window */
    /// log base 2 of requested window size
    pub(crate) wbits: c_uint,
    /// window size or zero if not using window
    pub(crate) wsize: u32,
    /// real size of the allocated window buffer, including padding
    pub(crate) wbufsize: u32,
    /// valid bytes in the window
    pub(crate) whave: u32,
    /// window write index
    pub(crate) wnext: u32,
    /// allocated sliding window, if needed
    pub(crate) window: *mut u8,

    /* bit accumulator */
    /// input bit accumulator
    pub(crate) hold: u64,
    /// number of bits in hold
    pub(crate) bits: c_uint,
    /* fixed and dynamic code tables */
    /// index bits for lencode
    pub(crate) lenbits: c_uint,
    /// starting table for length/literal codes
    pub(crate) lencode: *const code,
    /// starting table for distance codes
    pub(crate) distcode: *const code,
    /// index bits for distcode
    pub(crate) distbits: c_uint,
    /* for string and stored block copying */
    /// literal or length of data to copy
    pub(crate) length: u32,
    /// distance back to copy string from
    pub(crate) offset: c_uint,
    /* for table and code decoding */
    /// extra bits needed
    pub(crate) extra: c_uint,
    /* dynamic table building */
    /// number of code length code lengths
    pub(crate) ncode: c_uint,
    /// number of length code lengths
    pub(crate) nlen: c_uint,
    /// number of distance code lengths
    pub(crate) ndist: c_uint,
    /// number of code lengths in lens[]
    pub(crate) have: u32,
    /// next available space in codes[]
    pub(crate) next: *mut code,

    /// temporary storage for code lengths
    pub(crate) lens: [u16; 320],
    /// work area for code table building
    pub(crate) work: [u16; 288],
    /// space for code tables
    pub(crate) codes: [code; ENOUGH],

    /// struct for handling memory allocations
    pub(crate) alloc_bufs: *mut inflate_allocs,

    /// zlib header max distance (INFLATE_STRICT)
    #[cfg(feature = "inflate-strict")]
    pub(crate) dmax: c_uint,
    /// if false, allow invalid distance too far
    #[cfg(feature = "inflate-allow-invalid-dist")]
    pub(crate) sane: c_int,
}

unsafe extern "C" {
    #[cfg(not(feature = "zlib-compat"))]
    #[link_name = "zng_inflateInit"]
    pub(crate) fn inflateInit(strm: *mut z_stream) -> i32;
    #[cfg(feature = "zlib-compat")]
    fn inflateInit_(strm: *mut z_stream, version: *const c_char, stream_size: i32) -> i32;
    #[link_name = prefix!("inflate")]
    pub(crate) fn inflate(strm: *mut z_stream, flush: i32) -> i32;
    #[link_name = prefix!("inflateEnd")]
    pub(crate) fn inflateEnd(strm: *mut z_stream) -> i32;
}

/// inflateInit is a macro in zlib.h to allow checking the zlib version
/// and the compiler's view of z_stream
///
/// # Safety
///
/// `strm` must be valid for reads and writes.
#[cfg(feature = "zlib-compat")]
#[allow(non_snake_case)]
#[inline]
pub(crate) unsafe fn inflateInit(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees strm is valid and the version is a NUL terminated string.
    unsafe { inflateInit_(strm, ZLIB_VERSION.as_ptr(), size_of::<z_stream>() as i32) }
}
