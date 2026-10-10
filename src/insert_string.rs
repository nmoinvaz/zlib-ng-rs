//! insert_string.c -- make insert_string functions from static inlined functions
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use crate::deflate::deflate_state;
use crate::insert_string_p::{
    insert_knuth_batch_head_static, insert_knuth_batch_static, insert_roll_batch_static,
};

/// # Safety
///
/// `s` must point to a deflate_state with valid head and prev tables, and `window` must be valid
/// for reads of `str + count + 3` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn insert_knuth_batch(
    s: *mut deflate_state,
    window: *mut u8,
    str: u32,
    count: u32,
) {
    // SAFETY: the caller upholds the contract of insert_knuth_batch_static.
    unsafe { insert_knuth_batch_static(s, window, str, count) }
}

/// # Safety
///
/// `s` must point to a deflate_state with valid head and prev tables, and `window` must be valid
/// for reads of `str + count + 2` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn insert_roll_batch(
    s: *mut deflate_state,
    window: *mut u8,
    str: u32,
    count: u32,
) {
    // SAFETY: the caller upholds the contract of insert_roll_batch_static.
    unsafe { insert_roll_batch_static(s, window, str, count) }
}

/// # Safety
///
/// `s` must point to a deflate_state with a valid head table, and `window` must be valid for
/// reads of `str + count + 3` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn insert_knuth_batch_head(
    s: *mut deflate_state,
    window: *mut u8,
    str: u32,
    count: u32,
) {
    // SAFETY: the caller upholds the contract of insert_knuth_batch_head_static.
    unsafe { insert_knuth_batch_head_static(s, window, str, count) }
}
