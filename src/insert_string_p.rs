//! insert_string_p.h -- static single and batch hash insert functions
//!
//! Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use crate::deflate::{HASH_BITS, HASH_SIZE, Pos, deflate_state, w_mask};
use crate::zbuild::likely;
use crate::zmemory::zng_memread_4;
use crate::zutil::STD_MIN_MATCH;

const KNUTH_SHIFT: u32 = 32 - HASH_BITS;

#[inline(always)]
pub(crate) fn update_hash_knuth(val: u32) -> u32 {
    val.wrapping_mul(2654435761) >> KNUTH_SHIFT
}

const ROLL_MASK: u32 = (HASH_SIZE as u32 / 2) - 1;

/* ===========================================================================
 * Update a hash value with the given input byte
 * IN  assertion: all calls to UPDATE_HASH are made with consecutive
 *    input characters, so that a running hash key can be computed from the
 *    previous key instead of complete recalculation each time.
 */
#[inline(always)]
pub(crate) fn update_hash_roll(h: u32, val: u8) -> u32 {
    ((h << 5) ^ u32::from(val)) & ROLL_MASK
}

/* ===========================================================================
 * Insert string str in the dictionary using a pre-read value and set match_head
 * to the previous head of the hash chain (the most recent string with same hash key).
 * Return the previous length of the hash chain.
 */
/// # Safety
///
/// `s` must point to a deflate_state with valid head and prev tables.
#[inline(always)]
pub(crate) unsafe fn insert_knuth_val(s: *mut deflate_state, str: u32, val: u32) -> u32 {
    // SAFETY: the caller guarantees the state and its tables are valid. The hash is below
    // HASH_SIZE and the masked index is below w_size.
    unsafe {
        let h = update_hash_knuth(val);

        // Rust cannot tell that the table stores leave the state alone, so read the pointers and
        // the mask before them.
        let headp = (*s).head;
        let prevp = (*s).prev;
        let w_mask = w_mask(s);

        let head = u32::from(*headp.add(h as usize));
        if likely(head != str) {
            *prevp.add((str & w_mask) as usize) = head as Pos;
            *headp.add(h as usize) = str as Pos;
        }
        head
    }
}

/// Like insert_knuth, but leaves the prev link untouched. Used for deflate_quick, which only
/// inspects the chain head.
///
/// # Safety
///
/// `s` must point to a deflate_state with a valid head table, and `window` must be valid for
/// reads of `str + 4` bytes.
#[inline(always)]
pub(crate) unsafe fn insert_knuth_head(s: *mut deflate_state, window: *mut u8, str: u32) -> u32 {
    // SAFETY: the caller guarantees the state, its head table and the window bytes are valid. The
    // hash is below HASH_SIZE.
    unsafe {
        let val = u32::from_le(zng_memread_4(window.add(str as usize)));
        let h = update_hash_knuth(val);

        let slot = (*s).head.add(h as usize);
        let head = u32::from(*slot);
        *slot = str as Pos;
        head
    }
}

/* ===========================================================================
 * Insert string str using a pre-read value, returning the previous head of the
 * hash chain. The prev link is left untouched since deflate_quick only inspects
 * the chain head and never walks the chain.
 */
/// # Safety
///
/// `s` must point to a deflate_state with a valid head table.
#[inline(always)]
pub(crate) unsafe fn insert_knuth_val_head(s: *mut deflate_state, str: u32, val: u32) -> u32 {
    // SAFETY: the caller guarantees the state and its head table are valid. The hash is below
    // HASH_SIZE.
    unsafe {
        let h = update_hash_knuth(val);

        let slot = (*s).head.add(h as usize);
        let head = u32::from(*slot);
        *slot = str as Pos;
        head
    }
}

/* ===========================================================================
 * Insert string str in the dictionary and set match_head to the previous head
 * of the hash chain (the most recent string with same hash key). Return
 * the previous length of the hash chain.
 */
/// # Safety
///
/// `s` must point to a deflate_state with valid head and prev tables, and `window` must be valid
/// for reads of `str + 4` bytes.
#[inline(always)]
pub(crate) unsafe fn insert_knuth(s: *mut deflate_state, window: *mut u8, str: u32) -> u32 {
    // SAFETY: the caller guarantees the window bytes are valid and upholds the contract of
    // insert_knuth_val.
    unsafe {
        let strstart = window.add(str as usize);

        let val = u32::from_le(zng_memread_4(strstart));
        insert_knuth_val(s, str, val)
    }
}

/// # Safety
///
/// `s` must point to a deflate_state with valid head and prev tables, and `window` must be valid
/// for reads of `str + 3` bytes.
#[inline(always)]
pub(crate) unsafe fn insert_roll(s: *mut deflate_state, window: *mut u8, str: u32) -> u32 {
    // SAFETY: the caller guarantees the state, its tables and the window byte are valid. The hash
    // is below HASH_SIZE and the masked index is below w_size.
    unsafe {
        let strstart = window.add(str as usize + (STD_MIN_MATCH - 1));

        let headp = (*s).head;
        let prevp = (*s).prev;
        let w_mask = w_mask(s);

        let h = update_hash_roll((*s).ins_h, *strstart);
        (*s).ins_h = h;

        let head = u32::from(*headp.add(h as usize));
        if likely(head != str) {
            *prevp.add((str & w_mask) as usize) = head as Pos;
            *headp.add(h as usize) = str as Pos;
        }
        head
    }
}

/* ===========================================================================
 * Insert string str in the dictionary and set match_head to the previous head
 * of the hash chain (the most recent string with same hash key). Return
 * the previous length of the hash chain.
 * IN  assertion: all calls to insert_knuth_batch are made with consecutive
 *    input characters and the first STD_MIN_MATCH bytes of str are valid
 *    (except for the last STD_MIN_MATCH-1 bytes of the input file).
 */
/// # Safety
///
/// `s` must point to a deflate_state with valid head and prev tables, and `window` must be valid
/// for reads of `str + count + 3` bytes.
#[inline(always)]
pub(crate) unsafe fn insert_knuth_batch_static(
    s: *mut deflate_state,
    window: *mut u8,
    str: u32,
    count: u32,
) {
    // SAFETY: the caller guarantees the state, its tables and the window bytes are valid. The hash
    // is below HASH_SIZE and the masked index is below w_size.
    unsafe {
        let mut strstart = window.add(str as usize);
        let strend = strstart.add(count as usize);

        /* Local pointers to avoid indirection */
        let headp = (*s).head;
        let prevp = (*s).prev;
        let w_mask = w_mask(s);

        let mut idx = str;
        while strstart < strend {
            let val = u32::from_le(strstart.cast::<u32>().read_unaligned());
            let h = update_hash_knuth(val);

            let head = u32::from(*headp.add(h as usize));
            if likely(head != idx) {
                *prevp.add((idx & w_mask) as usize) = head as Pos;
                *headp.add(h as usize) = idx as Pos;
            }
            idx += 1;
            strstart = strstart.add(1);
        }
    }
}

/* ===========================================================================
 * Insert count strings read from the window, leaving the prev links untouched.
 * Used by fill_window during deflate_quick, which only inspects the chain head.
 */
/// # Safety
///
/// `s` must point to a deflate_state with a valid head table, and `window` must be valid for
/// reads of `str + count + 3` bytes.
#[inline(always)]
pub(crate) unsafe fn insert_knuth_batch_head_static(
    s: *mut deflate_state,
    window: *mut u8,
    str: u32,
    count: u32,
) {
    // SAFETY: the caller guarantees the state, its head table and the window bytes are valid. The
    // hash is below HASH_SIZE.
    unsafe {
        let mut strstart = window.add(str as usize);
        let strend = strstart.add(count as usize);
        let headp = (*s).head;

        let mut idx = str;
        while strstart < strend {
            let val = u32::from_le(strstart.cast::<u32>().read_unaligned());
            let h = update_hash_knuth(val);

            *headp.add(h as usize) = idx as Pos;
            idx += 1;
            strstart = strstart.add(1);
        }
    }
}

/// # Safety
///
/// `s` must point to a deflate_state with valid head and prev tables, and `window` must be valid
/// for reads of `str + count + 2` bytes.
#[inline(always)]
pub(crate) unsafe fn insert_roll_batch_static(
    s: *mut deflate_state,
    window: *mut u8,
    str: u32,
    count: u32,
) {
    // SAFETY: the caller guarantees the state, its tables and the window bytes are valid. The hash
    // is below HASH_SIZE and the masked index is below w_size.
    unsafe {
        let mut strstart = window.add(str as usize + (STD_MIN_MATCH - 1));
        let strend = strstart.add(count as usize);

        /* Local pointers to avoid indirection */
        let headp = (*s).head;
        let prevp = (*s).prev;
        let mut h = (*s).ins_h;
        let w_mask = w_mask(s);

        let mut idx = str;
        while strstart < strend {
            h = update_hash_roll(h, *strstart);

            let head = u32::from(*headp.add(h as usize));
            if likely(head != idx) {
                *prevp.add((idx & w_mask) as usize) = head as Pos;
                *headp.add(h as usize) = idx as Pos;
            }
            idx += 1;
            strstart = strstart.add(1);
        }
        (*s).ins_h = h;
    }
}
