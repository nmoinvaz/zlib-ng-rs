//! compare256.c -- 256 byte memory comparison with match length return
//! Copyright (C) 2020 Nathan Moinvaziri
//! For conditions of distribution and use, see copyright notice in zlib.h

use crate::deflate::deflate_state;
use crate::fallback_builtins::zng_first_diff_byte64;
use crate::match_tpl::{Compare256, longest_match};
use crate::zbuild::OPTIMAL_CMP;

/* 8-bit integer comparison for hardware without unaligned loads */
#[inline(always)]
fn compare256_8_static(src0: &[u8; 256], src1: &[u8; 256]) -> u32 {
    let mut len = 0;

    for (chunk0, chunk1) in src0.as_chunks::<8>().0.iter().zip(src1.as_chunks::<8>().0) {
        for (byte0, byte1) in chunk0.iter().zip(chunk1) {
            if byte0 != byte1 {
                return len;
            }
            len += 1;
        }
    }

    256
}

/* 64-bit integer comparison for hardware with unaligned loads */
#[inline(always)]
fn compare256_64_static(src0: &[u8; 256], src1: &[u8; 256]) -> u32 {
    let mut len = 0;

    for (chunk0, chunk1) in src0.as_chunks::<8>().0.iter().zip(src1.as_chunks::<8>().0) {
        let sv = u64::from_ne_bytes(*chunk0);
        let mv = u64::from_ne_bytes(*chunk1);
        let diff = sv ^ mv;
        if diff != 0 {
            return len + zng_first_diff_byte64(diff);
        }
        len += 8;
    }

    256
}

#[inline(always)]
fn compare256_static(src0: &[u8; 256], src1: &[u8; 256]) -> u32 {
    if OPTIMAL_CMP == 8 {
        compare256_8_static(src0, src1)
    } else {
        compare256_64_static(src0, src1)
    }
}

struct Generic;

impl Compare256 for Generic {
    #[inline(always)]
    fn compare256(src0: &[u8; 256], src1: &[u8; 256]) -> u32 {
        compare256_static(src0, src1)
    }
}

/// # Safety
///
/// `src0` and `src1` must be valid for reads of 256 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn compare256_8(src0: *const u8, src1: *const u8) -> u32 {
    // SAFETY: the caller guarantees both pointers are valid for reads of 256 bytes.
    unsafe { compare256_8_static(&*src0.cast(), &*src1.cast()) }
}

/// # Safety
///
/// `src0` and `src1` must be valid for reads of 256 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn compare256_64(src0: *const u8, src1: *const u8) -> u32 {
    // SAFETY: the caller guarantees both pointers are valid for reads of 256 bytes.
    unsafe { compare256_64_static(&*src0.cast(), &*src1.cast()) }
}

/// # Safety
///
/// `src0` and `src1` must be valid for reads of 256 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn compare256_c(src0: *const u8, src1: *const u8) -> u32 {
    // SAFETY: the caller guarantees both pointers are valid for reads of 256 bytes.
    unsafe { compare256_static(&*src0.cast(), &*src1.cast()) }
}

/// # Safety
///
/// `s` must point to a deflate_state that upholds the IN assertions of longest_match.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn longest_match_c(s: *mut deflate_state, cur_match: u32) -> u32 {
    // SAFETY: the caller upholds the contract of longest_match.
    unsafe { longest_match::<Generic, false, false>(s, cur_match) }
}

/// # Safety
///
/// `s` must point to a deflate_state that upholds the IN assertions of longest_match.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn longest_match_slow_knuth_c(s: *mut deflate_state, cur_match: u32) -> u32 {
    // SAFETY: the caller upholds the contract of longest_match.
    unsafe { longest_match::<Generic, true, false>(s, cur_match) }
}

/// # Safety
///
/// `s` must point to a deflate_state that upholds the IN assertions of longest_match.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn longest_match_slow_roll_c(s: *mut deflate_state, cur_match: u32) -> u32 {
    // SAFETY: the caller upholds the contract of longest_match.
    unsafe { longest_match::<Generic, true, true>(s, cur_match) }
}
