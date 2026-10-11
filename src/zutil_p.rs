//! zutil_p.h -- Private inline functions used internally in zlib-ng
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::ffi::c_void;

unsafe extern "C" {
    safe fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

// Zlib-ng's default alloc/free implementation, used unless
// application supplies its own alloc/free functions.
#[inline]
pub(crate) fn zng_alloc(size: usize) -> *mut c_void {
    malloc(size)
}

/// # Safety
///
/// `ptr` must be null or memory from zng_alloc that has not been freed.
#[inline]
pub(crate) unsafe fn zng_free(ptr: *mut c_void) {
    // SAFETY: the caller guarantees ptr came from malloc.
    unsafe { free(ptr) }
}
