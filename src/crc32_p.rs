//! crc32_p.h -- Private inline functions and macros shared with
//!              different computation of the CRC-32 checksum
//!              of a data stream.
//! Copyright (C) 2026 Nathan Moinvaziri
//! For conditions of distribution and use, see copyright notice in zlib.h

use crate::crc32_braid_tbl::CRC_TABLE;

#[inline(always)]
fn crc_do1(c: u32, byte: u8) -> u32 {
    CRC_TABLE[usize::from(c as u8 ^ byte)] ^ (c >> 8)
}

#[inline(always)]
fn crc_do2(c: u32, buf: [u8; 2]) -> u32 {
    crc_do1(crc_do1(c, buf[0]), buf[1])
}

#[inline(always)]
fn crc_do4(c: u32, buf: [u8; 4]) -> u32 {
    crc_do2(crc_do2(c, [buf[0], buf[1]]), [buf[2], buf[3]])
}

#[inline(always)]
fn crc_do8(c: u32, buf: [u8; 8]) -> u32 {
    crc_do4(
        crc_do4(c, [buf[0], buf[1], buf[2], buf[3]]),
        [buf[4], buf[5], buf[6], buf[7]],
    )
}

#[inline(always)]
pub(crate) fn crc32_copy_small<const MAX_LEN: usize>(mut crc: u32, buf: &[u8]) -> u32 {
    let mut buf = buf;
    if MAX_LEN >= 8 {
        let (chunks, rest) = buf.as_chunks::<8>();
        for &chunk in chunks {
            crc = crc_do8(crc, chunk);
        }
        buf = rest;
    }
    if buf.len() & 4 != 0
        && let Some((&quad, rest)) = buf.split_first_chunk::<4>()
    {
        crc = crc_do4(crc, quad);
        buf = rest;
    }
    if buf.len() & 2 != 0
        && let Some((&pair, rest)) = buf.split_first_chunk::<2>()
    {
        crc = crc_do2(crc, pair);
        buf = rest;
    }
    if buf.len() & 1 != 0
        && let Some(&byte) = buf.first()
    {
        crc = crc_do1(crc, byte);
    }

    crc
}
