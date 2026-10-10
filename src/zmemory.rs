//! zmemory.h -- Private inline functions used internally in zlib-ng
//! For conditions of distribution and use, see copyright notice in zlib.h

/// # Safety
///
/// `ptr` must be valid for reads of 4 bytes.
#[inline(always)]
pub(crate) unsafe fn zng_memread_4(ptr: *const u8) -> u32 {
    // SAFETY: the caller guarantees ptr is valid for reads of 4 bytes.
    unsafe { ptr.cast::<u32>().read_unaligned() }
}

/// # Safety
///
/// `ptr` must be valid for writes of 2 bytes.
#[inline(always)]
pub(crate) unsafe fn zng_memwrite_2(ptr: *mut u8, val: u16) {
    // SAFETY: the caller guarantees ptr is valid for writes of 2 bytes.
    unsafe { ptr.cast::<u16>().write_unaligned(val) }
}

/// # Safety
///
/// `ptr` must be valid for writes of 4 bytes.
#[cfg_attr(feature = "lit-mem", allow(dead_code))]
#[inline(always)]
pub(crate) unsafe fn zng_memwrite_4(ptr: *mut u8, val: u32) {
    // SAFETY: the caller guarantees ptr is valid for writes of 4 bytes.
    unsafe { ptr.cast::<u32>().write_unaligned(val) }
}

/// # Safety
///
/// `ptr` must be valid for reads of 8 bytes.
#[inline(always)]
pub(crate) unsafe fn zng_memread_8(ptr: *const u8) -> u64 {
    // SAFETY: the caller guarantees ptr is valid for reads of 8 bytes.
    unsafe { ptr.cast::<u64>().read_unaligned() }
}

/// # Safety
///
/// `ptr` must be valid for writes of 8 bytes.
#[inline(always)]
pub(crate) unsafe fn zng_memwrite_8(ptr: *mut u8, val: u64) {
    // SAFETY: the caller guarantees ptr is valid for writes of 8 bytes.
    unsafe { ptr.cast::<u64>().write_unaligned(val) }
}
