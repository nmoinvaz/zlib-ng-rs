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

/// Name of a symbol in the zlib compatible API or the zlib-ng native API
#[cfg(feature = "zlib-compat")]
macro_rules! prefix {
    ($name:literal) => {
        $name
    };
}
#[cfg(not(feature = "zlib-compat"))]
macro_rules! prefix {
    ($name:literal) => {
        concat!("zng_", $name)
    };
}
pub(crate) use prefix;

/// In zlib-compat some functions and types use unsigned long, but zlib-ng use size_t
#[cfg(feature = "zlib-compat")]
#[allow(non_camel_case_types)]
pub type z_uintmax_t = core::ffi::c_ulong;
#[cfg(not(feature = "zlib-compat"))]
#[allow(non_camel_case_types)]
pub type z_uintmax_t = usize;
