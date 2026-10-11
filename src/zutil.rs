//! zutil.h -- internal interface and configuration of the compression library
//! Copyright (C) 1995-2026 Jean-loup Gailly, Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! zutil.c -- target dependent utility functions for the compression library
//! Copyright (C) 1995-2026 Jean-loup Gailly
//! For conditions of distribution and use, see copyright notice in zlib.h

/* WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change. Applications should only use zlib.h.
*/

#![cfg_attr(feature = "no-quick-strategy", allow(dead_code))]

use core::ffi::{CStr, c_char, c_int, c_uint, c_ulong, c_void};

use crate::deflate::ZLIB_DEBUG;
use crate::zbuild::{align_diff, prefix, prefix3};
use crate::zconf::{MAX_MEM_LEVEL, MAX_WBITS, z_off_t};
#[cfg(feature = "zlib-compat")]
use crate::zlib::ZLIB_VERSION;
#[cfg(not(feature = "zlib-compat"))]
use crate::zlib::ZLIBNG_VERSION;
use crate::zlib::z_stream;
use crate::zutil_p::{zng_alloc, zng_free};

/// The table of error messages, which holds pointers and so needs a wrapper to be a static
#[repr(transparent)]
pub struct ErrorMessages([*const c_char; 10]);

// SAFETY: the table and the strings it points to are never written.
unsafe impl Sync for ErrorMessages {}

/// indexed by 2-zlib_error
#[allow(non_upper_case_globals)]
#[unsafe(export_name = prefix!("z_errmsg"))]
pub static z_errmsg: ErrorMessages = ErrorMessages([
    c"need dictionary".as_ptr(),      /* Z_NEED_DICT       2  */
    c"stream end".as_ptr(),           /* Z_STREAM_END      1  */
    c"".as_ptr(),                     /* Z_OK              0  */
    c"file error".as_ptr(),           /* Z_ERRNO         (-1) */
    c"stream error".as_ptr(),         /* Z_STREAM_ERROR  (-2) */
    c"data error".as_ptr(),           /* Z_DATA_ERROR    (-3) */
    c"insufficient memory".as_ptr(),  /* Z_MEM_ERROR     (-4) */
    c"buffer error".as_ptr(),         /* Z_BUF_ERROR     (-5) */
    c"incompatible version".as_ptr(), /* Z_VERSION_ERROR (-6) */
    c"".as_ptr(),
]);

/// The error message for an error code, ERR_MSG in C
#[inline]
pub(crate) fn err_msg(err: c_int) -> *const c_char {
    let index = if !(-6..=2).contains(&err) {
        9
    } else {
        (2 - err) as usize
    };
    // SAFETY: the index is below 10.
    unsafe { *z_errmsg.0.get_unchecked(index) }
}

/// Sets the message of the stream and hands back the error, ERR_RETURN in C. To be used only
/// when the state is known to be valid.
///
/// # Safety
///
/// `strm` must be valid for writes.
#[inline]
pub(crate) unsafe fn err_return(strm: *mut z_stream, err: c_int) -> c_int {
    // SAFETY: the caller guarantees strm is valid.
    unsafe { (*strm).msg = err_msg(err) };
    err
}

/* common constants */
const _: () = assert!(
    MAX_WBITS >= 9 && MAX_WBITS <= 15,
    "MAX_WBITS must be in 9..15"
);
/// default windowBits for decompression. MAX_WBITS is for compression only
pub(crate) const DEF_WBITS: i32 = MAX_WBITS;

/// initial adler-32 hash value
pub(crate) const ADLER32_INITIAL_VALUE: u32 = 1;
/// initial crc-32 hash value
pub(crate) const CRC32_INITIAL_VALUE: u32 = 0;

/// All codes must not exceed MAX_BITS bits
pub(crate) const MAX_BITS: usize = 15;
/// maximum number of extra distance bits
pub(crate) const MAX_DIST_EXTRA_BITS: u32 = 13;
/// maximum number of index bits for the first-level length code table
/// (the largest value assigned to state->lenbits)
pub(crate) const MAX_LEN_ROOT_BITS: u32 = 10;

/* The three kinds of block type */
pub(crate) const STORED_BLOCK: u32 = 0;
pub(crate) const STATIC_TREES: u32 = 1;
pub(crate) const DYN_TREES: u32 = 2;

/// preset dictionary flag in zlib header
pub(crate) const PRESET_DICT: u32 = 0x20;

/// gzip format overhead
pub(crate) const GZIP_WRAPLEN: usize = 18;

/// default memLevel
pub(crate) const DEF_MEM_LEVEL: i32 = if MAX_MEM_LEVEL >= 8 { 8 } else { MAX_MEM_LEVEL };

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

/* macros */

/// The first character of the version that the caller must have been built against
#[cfg(feature = "zlib-compat")]
pub(crate) const VERSION_0: u8 = ZLIB_VERSION.to_bytes()[0];
#[cfg(not(feature = "zlib-compat"))]
pub(crate) const VERSION_0: u8 = ZLIBNG_VERSION.to_bytes()[0];

/// Whether the caller was built against another library version or another z_stream,
/// CHECK_VER_STSIZE in C
///
/// # Safety
///
/// `version` must be null or point to at least one byte.
#[inline]
pub(crate) unsafe fn check_ver_stsize(version: *const c_char, stream_size: i32) -> bool {
    // SAFETY: the caller guarantees version is null or readable.
    unsafe {
        version.is_null()
            || *version != VERSION_0 as c_char
            || stream_size != size_of::<z_stream>() as i32
    }
}

const VSTRING: &[u8] = b" zlib-ng 2.3.90 devel\0";

#[allow(non_upper_case_globals)]
#[used]
#[unsafe(export_name = prefix3!("vstring"))]
pub static vstring: [u8; VSTRING.len()] = {
    let mut text = [0; VSTRING.len()];
    let mut i = 0;
    while i < text.len() {
        text[i] = VSTRING[i];
        i += 1;
    }
    text
};

#[cfg(feature = "zlib-compat")]
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn zlibVersion() -> *const c_char {
    ZLIB_VERSION.as_ptr()
}

#[cfg(not(feature = "zlib-compat"))]
#[unsafe(no_mangle)]
pub extern "C" fn zlibng_version() -> *const c_char {
    ZLIBNG_VERSION.as_ptr()
}

// The build reads the flags of the C sources that zlibCompileFlags reports.
#[cfg(feature = "c-layout")]
pub(crate) use crate::c_layout::PKZIP_BUG_WORKAROUND;
#[cfg(feature = "c-layout")]
use crate::c_layout::{NO_GZCOMPRESS, NO_GZIP, ZLIB_WINAPI};
/// The flags for a plain cargo build, which has no C sources to ask.
#[cfg(not(feature = "c-layout"))]
pub(crate) const PKZIP_BUG_WORKAROUND: usize = 0;
#[cfg(not(feature = "c-layout"))]
const NO_GZCOMPRESS: usize = 0;
#[cfg(not(feature = "c-layout"))]
const NO_GZIP: usize = 0;
#[cfg(not(feature = "c-layout"))]
const ZLIB_WINAPI: usize = 0;

// deflate and inflate always handle the gzip format here.
const _: () = assert!(NO_GZIP == 0, "NO_GZIP is not supported");

/// The two bit code that zlibCompileFlags reports for the size of a type
const fn size_code(size: usize) -> c_ulong {
    match size {
        2 => 0,
        4 => 1,
        8 => 2,
        _ => 3,
    }
}

#[unsafe(export_name = prefix!("zlibCompileFlags"))]
#[allow(non_snake_case)]
pub extern "C" fn zlibCompileFlags() -> c_ulong {
    let mut flags: c_ulong = 0;
    flags += size_code(size_of::<c_uint>());
    flags += size_code(size_of::<c_ulong>()) << 2;
    flags += size_code(size_of::<*const c_void>()) << 4;
    flags += size_code(size_of::<z_off_t>()) << 6;
    if ZLIB_DEBUG {
        flags += 1 << 8;
    }
    if ZLIB_WINAPI != 0 {
        flags += 1 << 10;
    }
    /* Bit 13 reserved for DYNAMIC_CRC_TABLE */
    if NO_GZCOMPRESS != 0 {
        flags += 1 << 16;
    }
    if NO_GZIP != 0 {
        flags += 1 << 17;
    }
    if PKZIP_BUG_WORKAROUND != 0 {
        flags += 1 << 20;
    }
    flags
}

/// The level of the trace output of the C sources, which they only read with ZLIB_DEBUG
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static mut z_verbose: c_int = 0;

/// Reports a failed assertion of the C sources, which they only call with ZLIB_DEBUG.
///
/// # Safety
///
/// `m` must point to a NUL terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn z_error(m: *const c_char) -> ! {
    unsafe extern "C" {
        #[cfg_attr(windows, link_name = "_write")]
        fn write(fd: c_int, buf: *const c_void, count: WriteCount) -> WriteResult;
        fn exit(status: c_int) -> !;
    }
    #[cfg(windows)]
    type WriteCount = c_uint;
    #[cfg(windows)]
    type WriteResult = c_int;
    #[cfg(not(windows))]
    type WriteCount = usize;
    #[cfg(not(windows))]
    type WriteResult = isize;

    // SAFETY: the caller guarantees m is a string, and stderr takes both writes whole or fails.
    unsafe {
        let message = CStr::from_ptr(m).to_bytes();
        write(
            2,
            message.as_ptr().cast::<c_void>(),
            message.len() as WriteCount,
        );
        write(2, c"\n".as_ptr().cast::<c_void>(), 1);
        exit(1)
    }
}

/* exported to allow conversion of error code to string for compress() and
 * uncompress()
 */
#[unsafe(export_name = prefix!("zError"))]
#[allow(non_snake_case)]
pub extern "C" fn zError(err: i32) -> *const c_char {
    err_msg(err)
}

/* memory allocation functions */

// Zlib-ng's default alloc/free implementation, used unless
// application supplies its own alloc/free functions.
/// # Safety
///
/// Has no requirements, and is unsafe to match alloc_func.
#[unsafe(export_name = prefix!("zcalloc"))]
pub unsafe extern "C" fn zcalloc(_opaque: *mut c_void, items: c_uint, size: c_uint) -> *mut c_void {
    zng_alloc((items as usize).wrapping_mul(size as usize))
}

/// # Safety
///
/// `ptr` must be null or memory from zcalloc that has not been freed.
#[unsafe(export_name = prefix!("zcfree"))]
pub unsafe extern "C" fn zcfree(_opaque: *mut c_void, ptr: *mut c_void) {
    // SAFETY: the caller guarantees ptr came from zng_alloc.
    unsafe { zng_free(ptr) }
}

/* Provide aligned allocations, only used by gz* code */
#[unsafe(no_mangle)]
pub extern "C" fn zng_alloc_aligned(size: c_uint, align: c_uint) -> *mut c_void {
    /* Allocate enough memory for proper alignment and to store the original memory pointer */
    let alloc_size = (size_of::<*mut c_void>() as u32)
        .wrapping_add(size)
        .wrapping_add(align);
    let ptr = zng_alloc(alloc_size as usize);
    if ptr.is_null() {
        return ptr;
    }

    /* Calculate return pointer address with space enough to store original pointer */
    let mut offset = align_diff(ptr, align as usize);
    if offset < size_of::<*mut c_void>() {
        offset += align as usize;
    }

    // SAFETY: the allocation holds a pointer, size bytes and align bytes. The offset is at least
    // the size of a pointer and less than that plus align, so the pointer slot and the size bytes
    // behind it are inside the allocation.
    unsafe {
        let return_ptr = ptr.cast::<u8>().add(offset);
        /* Store the original pointer for free() */
        return_ptr
            .sub(size_of::<*mut c_void>())
            .cast::<*mut c_void>()
            .write_unaligned(ptr);
        /* Return properly aligned pointer in allocation */
        return_ptr.cast::<c_void>()
    }
}

/// # Safety
///
/// `ptr` must be null or memory from zng_alloc_aligned that has not been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_free_aligned(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: zng_alloc_aligned stored the pointer of the allocation in front of ptr.
    unsafe {
        /* Calculate offset to original memory allocation pointer */
        let free_ptr = ptr
            .cast::<u8>()
            .sub(size_of::<*mut c_void>())
            .cast::<*mut c_void>()
            .read_unaligned();

        /* Free original memory allocation */
        zng_free(free_ptr);
    }
}
