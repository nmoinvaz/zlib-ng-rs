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

/* OPTIMAL_CMP values determine the comparison width:
 * 64: Best for 64-bit architectures with unaligned access
 * 32: Best for 32-bit architectures with unaligned access
 * 16: Safe default for unknown architectures
 * 8:  Safe fallback for architectures without unaligned access
 */
/// The build takes the value that the C sources compute.
#[cfg(feature = "c-layout")]
pub(crate) use crate::c_layout::OPTIMAL_CMP;
/// The value for a plain cargo build, which has no C sources to ask.
#[cfg(not(feature = "c-layout"))]
pub(crate) const OPTIMAL_CMP: u32 = if cfg!(target_pointer_width = "64") {
    64
} else if cfg!(target_pointer_width = "32") {
    32
} else {
    16
};

#[cold]
#[inline]
fn cold() {}

/// Marks a condition as usually true, like LIKELY in zbuild.h. The branch hints in core::hint
/// are not stable yet, so the unexpected side calls a cold function instead.
#[inline(always)]
pub(crate) fn likely(condition: bool) -> bool {
    if !condition {
        cold();
    }
    condition
}

/// Marks a condition as usually false, like UNLIKELY in zbuild.h.
#[inline(always)]
pub(crate) fn unlikely(condition: bool) -> bool {
    if condition {
        cold();
    }
    condition
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

/// Name of a symbol that carries a prefix in both APIs, PREFIX3 in C
#[cfg(feature = "zlib-compat")]
macro_rules! prefix3 {
    ($name:literal) => {
        concat!("z_", $name)
    };
}
#[cfg(not(feature = "zlib-compat"))]
macro_rules! prefix3 {
    ($name:literal) => {
        concat!("zng_", $name)
    };
}
pub(crate) use prefix3;

/// In zlib-compat the checksums use unsigned long, but zlib-ng use uint32_t
#[cfg(feature = "zlib-compat")]
#[allow(non_camel_case_types)]
pub type z_checksum_t = core::ffi::c_ulong;
#[cfg(not(feature = "zlib-compat"))]
#[allow(non_camel_case_types)]
pub type z_checksum_t = u32;

/// In zlib-compat some functions and types use unsigned long, but zlib-ng use size_t
#[cfg(feature = "zlib-compat")]
#[allow(non_camel_case_types)]
pub type z_uintmax_t = core::ffi::c_ulong;
#[cfg(not(feature = "zlib-compat"))]
#[allow(non_camel_case_types)]
pub type z_uintmax_t = usize;
