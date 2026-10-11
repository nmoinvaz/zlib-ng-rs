//! functable.h -- Struct containing function pointers to optimized functions
//! Copyright (C) 2017 Hans Kristian Rosbach
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! functable.c is still built from C. With runtime CPU detection the Rust sources read its
//! function table directly, the way FUNCTABLE_CALL does. Without it the native functions are
//! chosen by C macros, so the calls go through small entry points in functable.c.

#[cfg(feature = "runtime-cpu-detection")]
use core::ffi::c_int;

use crate::deflate::deflate_state;
use crate::zlib::z_stream;

/// Whether the function table exists, the opposite of DISABLE_RUNTIME_CPU_DETECTION in C
#[cfg_attr(not(feature = "c-layout"), allow(dead_code))]
pub(crate) const RUNTIME_CPU_DETECTION: bool = cfg!(feature = "runtime-cpu-detection");

#[cfg(feature = "runtime-cpu-detection")]
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
pub(crate) struct functable_s {
    pub(crate) force_init: unsafe extern "C" fn() -> c_int,
    pub(crate) adler32: unsafe extern "C" fn(adler: u32, buf: *const u8, len: usize) -> u32,
    pub(crate) adler32_copy:
        unsafe extern "C" fn(adler: u32, dst: *mut u8, src: *const u8, len: usize) -> u32,
    pub(crate) chunkmemset_safe:
        unsafe extern "C" fn(out: *mut u8, from: *mut u8, len: usize, left: usize) -> *mut u8,
    pub(crate) compare256: unsafe extern "C" fn(src0: *const u8, src1: *const u8) -> u32,
    pub(crate) crc32: unsafe extern "C" fn(crc: u32, buf: *const u8, len: usize) -> u32,
    pub(crate) crc32_copy:
        unsafe extern "C" fn(crc: u32, dst: *mut u8, src: *const u8, len: usize) -> u32,
    pub(crate) inflate_fast: unsafe extern "C" fn(strm: *mut z_stream, start: u32),
    pub(crate) inflate_fast_safe: unsafe extern "C" fn(strm: *mut z_stream, start: u32),
    pub(crate) longest_match: unsafe extern "C" fn(s: *mut deflate_state, cur_match: u32) -> u32,
    pub(crate) longest_match_slow_knuth:
        unsafe extern "C" fn(s: *mut deflate_state, cur_match: u32) -> u32,
    pub(crate) longest_match_slow_roll:
        unsafe extern "C" fn(s: *mut deflate_state, cur_match: u32) -> u32,
    pub(crate) slide_hash: unsafe extern "C" fn(s: *mut deflate_state),
    pub(crate) slide_hash_head: unsafe extern "C" fn(s: *mut deflate_state),
}

#[cfg(feature = "runtime-cpu-detection")]
unsafe extern "C" {
    // The C side replaces the entries once, when it detects the CPU features.
    static mut functable: functable_s;
}

#[cfg(not(feature = "runtime-cpu-detection"))]
unsafe extern "C" {
    fn functable_slide_hash(s: *mut deflate_state);
    fn functable_slide_hash_head(s: *mut deflate_state);
    // The native functions that FUNCTABLE_FPTR names, as pointers.
    safe static functable_longest_match_slow_knuth:
        unsafe extern "C" fn(s: *mut deflate_state, cur_match: u32) -> u32;
    safe static functable_longest_match_slow_roll:
        unsafe extern "C" fn(s: *mut deflate_state, cur_match: u32) -> u32;
    fn functable_adler32(adler: u32, buf: *const u8, len: usize) -> u32;
    fn functable_adler32_copy(adler: u32, dst: *mut u8, src: *const u8, len: usize) -> u32;
    fn functable_chunkmemset_safe(out: *mut u8, from: *mut u8, len: usize, left: usize) -> *mut u8;
    fn functable_compare256(src0: *const u8, src1: *const u8) -> u32;
    fn functable_crc32(crc: u32, buf: *const u8, len: usize) -> u32;
    fn functable_crc32_copy(crc: u32, dst: *mut u8, src: *const u8, len: usize) -> u32;
    fn functable_inflate_fast(strm: *mut z_stream, start: u32);
    fn functable_inflate_fast_safe(strm: *mut z_stream, start: u32);
    fn functable_longest_match(s: *mut deflate_state, cur_match: u32) -> u32;
}

/// Calls one entry of the function table, FUNCTABLE_CALL in C.
macro_rules! functable_call {
    ($(#[$attr:meta])* $name:ident, $entry:ident, ($($arg:ident: $ty:ty),*) -> $ret:ty) => {
        $(#[$attr])*
        #[inline(always)]
        pub(crate) unsafe fn $name($($arg: $ty),*) -> $ret {
            // SAFETY: the caller upholds the contract of the function behind the entry. Reading
            // the pointer matches what the C sources do.
            #[cfg(feature = "runtime-cpu-detection")]
            return unsafe { ((&raw const functable.$name).read())($($arg),*) };
            // SAFETY: the caller upholds the contract of the function behind the entry.
            #[cfg(not(feature = "runtime-cpu-detection"))]
            return unsafe { $entry($($arg),*) };
        }
    };
}

functable_call!(
    /// # Safety
    ///
    /// `buf` must be valid for reads of `len` bytes.
    adler32, functable_adler32, (adler: u32, buf: *const u8, len: usize) -> u32
);
functable_call!(
    /// # Safety
    ///
    /// `src` must be valid for reads and `dst` for writes of `len` bytes.
    adler32_copy, functable_adler32_copy, (adler: u32, dst: *mut u8, src: *const u8, len: usize) -> u32
);
functable_call!(
    /// # Safety
    ///
    /// `out` must be valid for writes of `left` bytes, and `from` for reads of the bytes that are
    /// copied, which may be bytes that this copy writes.
    chunkmemset_safe, functable_chunkmemset_safe, (out: *mut u8, from: *mut u8, len: usize, left: usize) -> *mut u8
);
functable_call!(
    /// # Safety
    ///
    /// `src0` and `src1` must be valid for reads of 256 bytes.
    compare256, functable_compare256, (src0: *const u8, src1: *const u8) -> u32
);
functable_call!(
    /// # Safety
    ///
    /// `buf` must be valid for reads of `len` bytes.
    crc32, functable_crc32, (crc: u32, buf: *const u8, len: usize) -> u32
);
functable_call!(
    /// # Safety
    ///
    /// `src` must be valid for reads and `dst` for writes of `len` bytes.
    crc32_copy, functable_crc32_copy, (crc: u32, dst: *mut u8, src: *const u8, len: usize) -> u32
);
functable_call!(
    /// # Safety
    ///
    /// `strm` must be a valid inflate stream that upholds the entry assumptions of inflate_fast.
    inflate_fast, functable_inflate_fast, (strm: *mut z_stream, start: u32) -> ()
);
functable_call!(
    /// # Safety
    ///
    /// `strm` must be a valid inflate stream that upholds the entry assumptions of inflate_fast
    /// in its safe mode.
    inflate_fast_safe, functable_inflate_fast_safe, (strm: *mut z_stream, start: u32) -> ()
);
functable_call!(
    /// # Safety
    ///
    /// `s` must point to a deflate_state that upholds the IN assertions of longest_match.
    longest_match, functable_longest_match, (s: *mut deflate_state, cur_match: u32) -> u32
);
functable_call!(
    /// # Safety
    ///
    /// `s` must point to a deflate_state with valid head and prev tables.
    slide_hash, functable_slide_hash, (s: *mut deflate_state) -> ()
);
functable_call!(
    /// # Safety
    ///
    /// `s` must point to a deflate_state with a valid head table.
    slide_hash_head, functable_slide_hash_head, (s: *mut deflate_state) -> ()
);

/// Initializes the function table, FUNCTABLE_INIT in C. Returns whether that failed, which
/// cannot happen without runtime CPU detection because there is no table then.
#[inline(always)]
pub(crate) fn force_init_failed() -> bool {
    // SAFETY: the entry always holds a function, and reading it matches what the C sources do.
    #[cfg(feature = "runtime-cpu-detection")]
    return unsafe { ((&raw const functable.force_init).read())() != 0 };
    #[cfg(not(feature = "runtime-cpu-detection"))]
    return false;
}

/// The function that FUNCTABLE_FPTR(longest_match_slow_knuth) names in C
#[inline(always)]
pub(crate) fn longest_match_slow_knuth_fptr()
-> unsafe extern "C" fn(s: *mut deflate_state, cur_match: u32) -> u32 {
    // SAFETY: the entry always holds a function, and reading it matches what the C sources do.
    #[cfg(feature = "runtime-cpu-detection")]
    return unsafe { (&raw const functable.longest_match_slow_knuth).read() };
    #[cfg(not(feature = "runtime-cpu-detection"))]
    return functable_longest_match_slow_knuth;
}

/// The function that FUNCTABLE_FPTR(longest_match_slow_roll) names in C
#[inline(always)]
pub(crate) fn longest_match_slow_roll_fptr()
-> unsafe extern "C" fn(s: *mut deflate_state, cur_match: u32) -> u32 {
    // SAFETY: the entry always holds a function, and reading it matches what the C sources do.
    #[cfg(feature = "runtime-cpu-detection")]
    return unsafe { (&raw const functable.longest_match_slow_roll).read() };
    #[cfg(not(feature = "runtime-cpu-detection"))]
    return functable_longest_match_slow_roll;
}
