//! crc32_braid_comb.c -- compute the CRC-32 of a data stream
//! Copyright (C) 1995-2026 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! This interleaved implementation of a CRC makes use of pipelined multiple
//! arithmetic-logic units, commonly found in modern CPU cores. It is due to
//! Kadatch and Jenkins (2010). See doc/crc-doc.1.0.pdf in this distribution.

// The checksum and offset types are aliases whose widths depend on the build.
#![allow(clippy::unnecessary_cast, clippy::useless_conversion)]

#[cfg(feature = "zlib-compat")]
use core::ffi::c_ulong;

use crate::crc32_braid_comb_p::{multmodp, x2nmodp};
use crate::zbuild::{prefix, z_checksum_t};
#[cfg(feature = "zlib-compat")]
use crate::zconf::z_off_t;
use crate::zconf::z_off64_t;

/* ========================================================================= */
fn crc32_combine_(crc1: u32, crc2: u32, len2: i64) -> u32 {
    if len2 < 0 {
        return 0;
    }
    multmodp(x2nmodp(len2, 3), crc1) ^ crc2
}
fn crc32_combine_gen_(len2: i64) -> u32 {
    if len2 < 0 {
        return 0;
    }
    x2nmodp(len2, 3)
}
fn crc32_combine_op_(crc1: u32, crc2: u32, op: u32) -> u32 {
    multmodp(op, crc1) ^ crc2
}

/* ========================================================================= */

#[cfg(feature = "zlib-compat")]
#[unsafe(export_name = "crc32_combine")]
pub extern "C" fn crc32_combine(crc1: c_ulong, crc2: c_ulong, len2: z_off_t) -> c_ulong {
    c_ulong::from(crc32_combine_(crc1 as u32, crc2 as u32, i64::from(len2)))
}
#[cfg_attr(feature = "zlib-compat", unsafe(export_name = "crc32_combine64"))]
#[cfg_attr(
    not(feature = "zlib-compat"),
    unsafe(export_name = "zng_crc32_combine")
)]
pub extern "C" fn crc32_combine64(
    crc1: z_checksum_t,
    crc2: z_checksum_t,
    len2: z_off64_t,
) -> z_checksum_t {
    z_checksum_t::from(crc32_combine_(crc1 as u32, crc2 as u32, i64::from(len2)))
}
#[cfg(feature = "zlib-compat")]
#[unsafe(export_name = "crc32_combine_gen")]
pub extern "C" fn crc32_combine_gen(len2: z_off_t) -> c_ulong {
    c_ulong::from(crc32_combine_gen_(i64::from(len2)))
}
#[cfg_attr(feature = "zlib-compat", unsafe(export_name = "crc32_combine_gen64"))]
#[cfg_attr(
    not(feature = "zlib-compat"),
    unsafe(export_name = "zng_crc32_combine_gen")
)]
pub extern "C" fn crc32_combine_gen64(len2: z_off64_t) -> z_checksum_t {
    z_checksum_t::from(crc32_combine_gen_(i64::from(len2)))
}
#[unsafe(export_name = prefix!("crc32_combine_op"))]
pub extern "C" fn crc32_combine_op(
    crc1: z_checksum_t,
    crc2: z_checksum_t,
    op: z_checksum_t,
) -> z_checksum_t {
    z_checksum_t::from(crc32_combine_op_(crc1 as u32, crc2 as u32, op as u32))
}

/* ========================================================================= */
