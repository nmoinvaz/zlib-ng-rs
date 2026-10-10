//! Declarations for the functions of inflate.c that are still built from C.

#[cfg(feature = "zlib-compat")]
use core::ffi::c_char;

use crate::zbuild::prefix;
#[cfg(feature = "zlib-compat")]
use crate::zlib::ZLIB_VERSION;
use crate::zlib::z_stream;

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
