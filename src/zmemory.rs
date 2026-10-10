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
/// `ptr` must be valid for reads of 8 bytes.
#[inline(always)]
pub(crate) unsafe fn zng_memread_8(ptr: *const u8) -> u64 {
    // SAFETY: the caller guarantees ptr is valid for reads of 8 bytes.
    unsafe { ptr.cast::<u64>().read_unaligned() }
}
