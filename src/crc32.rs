//! crc32.c -- compute the CRC-32 of a data stream
//! Copyright (C) 1995-2026 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! This interleaved implementation of a CRC makes use of pipelined multiple
//! arithmetic-logic units, commonly found in modern CPU cores. It is due to
//! Kadatch and Jenkins (2010). See doc/crc-doc.1.0.pdf in this distribution.

// The checksum type is an alias whose width depends on the build.
#![allow(clippy::unnecessary_cast, clippy::useless_conversion)]

use core::slice;

use crate::crc32_braid_tbl::CRC_TABLE;
use crate::crc32_p::crc32_copy_small;
use crate::functable;
use crate::zbuild::{prefix, unlikely, z_checksum_t};
use crate::zutil::CRC32_INITIAL_VALUE;

/* ========================================================================= */

#[unsafe(export_name = prefix!("get_crc_table"))]
pub extern "C" fn get_crc_table() -> *const u32 {
    CRC_TABLE.as_ptr()
}

/* crc32 function meant for short buffers like gzip headers */
/// # Safety
///
/// `buf` must be valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crc32_small(crc: u32, buf: *const u8, len: usize) -> u32 {
    if unlikely(len >= 32) {
        // SAFETY: the caller guarantees buf is valid for reads of len bytes.
        return unsafe { functable::crc32(crc, buf, len) };
    }
    if len == 0 {
        return crc;
    }

    // SAFETY: the caller guarantees buf is valid for reads of len bytes.
    !crc32_copy_small::<32>(!crc, unsafe { slice::from_raw_parts(buf, len) })
}

/// # Safety
///
/// `buf` must be null or valid for reads of `len` bytes.
#[unsafe(export_name = prefix!("crc32_z"))]
pub unsafe extern "C" fn crc32_z(crc: z_checksum_t, buf: *const u8, len: usize) -> z_checksum_t {
    if buf.is_null() {
        return z_checksum_t::from(CRC32_INITIAL_VALUE);
    }
    // SAFETY: the caller guarantees buf is valid for reads of len bytes.
    z_checksum_t::from(unsafe { functable::crc32(crc as u32, buf, len) })
}

/// # Safety
///
/// `buf` must be null or valid for reads of `len` bytes.
#[unsafe(export_name = prefix!("crc32"))]
pub unsafe extern "C" fn crc32(crc: z_checksum_t, buf: *const u8, len: u32) -> z_checksum_t {
    if buf.is_null() {
        return z_checksum_t::from(CRC32_INITIAL_VALUE);
    }
    // SAFETY: the caller guarantees buf is valid for reads of len bytes.
    z_checksum_t::from(unsafe { functable::crc32(crc as u32, buf, len as usize) })
}
