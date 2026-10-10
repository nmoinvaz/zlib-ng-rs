//! Declarations for the functions of deflate.c that are still built from C.

#[cfg(feature = "zlib-compat")]
use core::ffi::c_char;

use crate::zbuild::prefix;
#[cfg(feature = "zlib-compat")]
use crate::zlib::ZLIB_VERSION;
use crate::zlib::z_stream;

unsafe extern "C" {
    #[cfg(not(feature = "zlib-compat"))]
    #[link_name = "zng_deflateInit"]
    pub(crate) fn deflateInit(strm: *mut z_stream, level: i32) -> i32;
    #[cfg(feature = "zlib-compat")]
    fn deflateInit_(
        strm: *mut z_stream,
        level: i32,
        version: *const c_char,
        stream_size: i32,
    ) -> i32;
    #[link_name = prefix!("deflate")]
    pub(crate) fn deflate(strm: *mut z_stream, flush: i32) -> i32;
    #[link_name = prefix!("deflateEnd")]
    pub(crate) fn deflateEnd(strm: *mut z_stream) -> i32;
}

/// deflateInit is a macro in zlib.h to allow checking the zlib version
/// and the compiler's view of z_stream
///
/// # Safety
///
/// `strm` must be valid for reads and writes.
#[cfg(feature = "zlib-compat")]
#[allow(non_snake_case)]
#[inline]
pub(crate) unsafe fn deflateInit(strm: *mut z_stream, level: i32) -> i32 {
    // SAFETY: the caller guarantees strm is valid and the version is a NUL terminated string.
    unsafe {
        deflateInit_(
            strm,
            level,
            ZLIB_VERSION.as_ptr(),
            size_of::<z_stream>() as i32,
        )
    }
}
