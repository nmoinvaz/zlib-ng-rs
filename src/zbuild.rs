/// Number of bytes needed to align ptr to the next alignment boundary
#[inline(always)]
pub(crate) fn align_diff<T>(ptr: *const T, align: usize) -> usize {
    align.wrapping_sub(ptr.addr() & (align - 1)) & (align - 1)
}

/// Round down value to the nearest multiple of align (align must be power of 2)
#[inline(always)]
pub(crate) fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}
