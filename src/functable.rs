//! functable.h -- Struct containing function pointers to optimized functions
//! Copyright (C) 2017 Hans Kristian Rosbach
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! functable.c is still built from C. With runtime CPU detection the Rust sources read its
//! function table directly, the way FUNCTABLE_CALL does. Without it the native functions are
//! chosen by C macros, so the calls go through small entry points in functable.c.

#[cfg(feature = "runtime-cpu-detection")]
use core::ffi::c_int;

#[cfg(feature = "runtime-cpu-detection")]
use crate::deflate::deflate_state;
#[cfg(feature = "runtime-cpu-detection")]
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
    fn functable_adler32(adler: u32, buf: *const u8, len: usize) -> u32;
    fn functable_crc32(crc: u32, buf: *const u8, len: usize) -> u32;
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
    /// `buf` must be valid for reads of `len` bytes.
    crc32, functable_crc32, (crc: u32, buf: *const u8, len: usize) -> u32
);
