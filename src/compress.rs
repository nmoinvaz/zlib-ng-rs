//! compress.c -- compress a memory buffer
//! Copyright (C) 1995-2026 Jean-loup Gailly, Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

#![allow(non_snake_case)]

#[cfg(feature = "zlib-compat")]
use core::ffi::c_ulong;
use core::{mem, ptr};

use crate::deflate::{deflate, deflateEnd, deflateInit};
use crate::zbuild::{prefix, z_uintmax_t};
use crate::zlib::{
    Z_DEFAULT_COMPRESSION, Z_FINISH, Z_NO_FLUSH, Z_OK, Z_STREAM_END, Z_STREAM_ERROR, z_stream,
};
use crate::zutil::ZLIB_WRAPLEN;
#[cfg(not(feature = "no-quick-strategy"))]
use crate::zutil::{DEFLATE_BLOCK_OVERHEAD, deflate_quick_overhead};

/* ===========================================================================
 *  Architecture-specific hooks.
 */
#[cfg(feature = "s390-dfltcc-deflate")]
use crate::arch::s390::dfltcc_common::deflate_bound_complen;
/* Returns the upper bound on compressed data length based on uncompressed data length, assuming
 * default settings. Zero means that arch-specific deflation code behaves identically to the
 * regular zlib-ng algorithms. */
#[cfg(not(feature = "s390-dfltcc-deflate"))]
#[inline(always)]
const fn deflate_bound_complen(_source_len: usize) -> usize {
    0
}

/* ===========================================================================
     Compresses the source buffer into the destination buffer. The level
   parameter has the same meaning as in deflateInit.  sourceLen is the byte
   length of the source buffer. Upon entry, destLen is the total size of the
   destination buffer, which must be at least 0.1% larger than sourceLen plus
   12 bytes. Upon exit, destLen is the actual size of the compressed buffer.

     compress2 returns Z_OK if success, Z_MEM_ERROR if there was not enough
   memory, Z_BUF_ERROR if there was not enough room in the output buffer,
   Z_STREAM_ERROR if the level parameter is invalid.
*/
/// # Safety
///
/// `dest` must be valid for writes of `*dest_len` bytes, `source` must be valid for reads of
/// `source_len` bytes, and `dest_len` must be null or valid for reads and writes.
#[cfg_attr(feature = "zlib-compat", unsafe(export_name = "compress2_z"))]
#[cfg_attr(not(feature = "zlib-compat"), unsafe(export_name = "zng_compress2"))]
pub unsafe extern "C" fn compress2_z(
    dest: *mut u8,
    dest_len: *mut usize,
    source: *const u8,
    mut source_len: usize,
    level: i32,
) -> i32 {
    // SAFETY: the caller guarantees dest_len is null or valid, and that the buffers are valid for
    // the lengths given. The stream is only passed to deflate between deflateInit and deflateEnd.
    unsafe {
        if (source_len > 0 && source.is_null())
            || dest_len.is_null()
            || (*dest_len > 0 && dest.is_null())
        {
            return Z_STREAM_ERROR;
        }

        let mut left = *dest_len;
        *dest_len = 0;

        let mut stream: z_stream = mem::zeroed();
        stream.zalloc = None;
        stream.zfree = None;
        stream.opaque = ptr::null_mut();

        let mut err = deflateInit(&mut stream, level);
        if err != Z_OK {
            return err;
        }

        stream.next_out = dest;
        stream.avail_out = 0;
        stream.next_in = source;
        stream.avail_in = 0;

        loop {
            if stream.avail_out == 0 {
                stream.avail_out = left.min(u32::MAX as usize) as u32;
                left -= stream.avail_out as usize;
            }
            if stream.avail_in == 0 {
                stream.avail_in = source_len.min(u32::MAX as usize) as u32;
                source_len -= stream.avail_in as usize;
            }
            err = deflate(
                &mut stream,
                if source_len != 0 {
                    Z_NO_FLUSH
                } else {
                    Z_FINISH
                },
            );
            if err != Z_OK {
                break;
            }
        }

        *dest_len = stream.total_out as usize;
        deflateEnd(&mut stream);
        if err == Z_STREAM_END { Z_OK } else { err }
    }
}

/* ===========================================================================
 */
/// # Safety
///
/// `dest` must be valid for writes of `*dest_len` bytes, `source` must be valid for reads of
/// `source_len` bytes, and `dest_len` must be null or valid for reads and writes.
#[unsafe(export_name = prefix!("compress"))]
pub unsafe extern "C" fn compress(
    dest: *mut u8,
    dest_len: *mut z_uintmax_t,
    source: *const u8,
    source_len: z_uintmax_t,
) -> i32 {
    // SAFETY: the caller upholds the contract of compress2.
    #[cfg(feature = "zlib-compat")]
    return unsafe { compress2(dest, dest_len, source, source_len, Z_DEFAULT_COMPRESSION) };
    // SAFETY: the caller upholds the contract of compress2.
    #[cfg(not(feature = "zlib-compat"))]
    return unsafe { compress2_z(dest, dest_len, source, source_len, Z_DEFAULT_COMPRESSION) };
}

/* ===========================================================================
   If the default memLevel or windowBits for deflateInit() is changed, then
   this function needs to be updated.
*/
#[cfg_attr(feature = "zlib-compat", unsafe(export_name = "compressBound_z"))]
#[cfg_attr(
    not(feature = "zlib-compat"),
    unsafe(export_name = "zng_compressBound")
)]
pub extern "C" fn compressBound_z(source_len: usize) -> usize {
    let complen = deflate_bound_complen(source_len);

    if complen > 0 {
        /* Architecture-specific code provided an upper bound. */
        let bound = complen.wrapping_add(ZLIB_WRAPLEN);
        return if bound < source_len {
            usize::MAX
        } else {
            bound
        };
    }

    #[cfg(not(feature = "no-quick-strategy"))]
    let bound = source_len /* The source size itself */
        .wrapping_add(usize::from(source_len == 0)) /* Always at least one byte for any input */
        .wrapping_add(usize::from(source_len < 9)) /* One extra byte for lengths less than 9 */
        .wrapping_add(deflate_quick_overhead(source_len)) /* Source encoding overhead, padded to next full byte */
        .wrapping_add(DEFLATE_BLOCK_OVERHEAD) /* Deflate block overhead bytes */
        .wrapping_add(ZLIB_WRAPLEN); /* zlib wrapper */
    #[cfg(feature = "no-quick-strategy")]
    let bound = source_len
        .wrapping_add(source_len >> 4)
        .wrapping_add(7)
        .wrapping_add(ZLIB_WRAPLEN);
    if bound < source_len {
        usize::MAX
    } else {
        bound
    }
}

#[cfg(feature = "zlib-compat")]
#[unsafe(export_name = "compressBound")]
pub extern "C" fn compressBound(source_len: c_ulong) -> c_ulong {
    let bound = compressBound_z(source_len as usize);
    bound.min(c_ulong::MAX as usize) as c_ulong
}

/// # Safety
///
/// `dest` must be valid for writes of `*dest_len` bytes, `source` must be valid for reads of
/// `source_len` bytes, and `dest_len` must be null or valid for reads and writes.
#[cfg(feature = "zlib-compat")]
#[unsafe(export_name = "compress2")]
pub unsafe extern "C" fn compress2(
    dest: *mut u8,
    dest_len: *mut c_ulong,
    source: *const u8,
    source_len: c_ulong,
    level: i32,
) -> i32 {
    // SAFETY: the caller guarantees dest_len is null or valid, and got is a valid local.
    unsafe {
        let mut got = if dest_len.is_null() {
            0
        } else {
            *dest_len as usize
        };
        let ret = compress2_z(dest, &mut got, source, source_len as usize, level);
        if !dest_len.is_null() {
            *dest_len = got as c_ulong;
        }
        ret
    }
}

/// # Safety
///
/// `dest` must be valid for writes of `*dest_len` bytes, `source` must be valid for reads of
/// `source_len` bytes, and `dest_len` must be null or valid for reads and writes.
#[cfg(feature = "zlib-compat")]
#[unsafe(export_name = "compress_z")]
pub unsafe extern "C" fn compress_z(
    dest: *mut u8,
    dest_len: *mut usize,
    source: *const u8,
    source_len: usize,
) -> i32 {
    // SAFETY: the caller upholds the contract of compress2_z.
    unsafe { compress2_z(dest, dest_len, source, source_len, Z_DEFAULT_COMPRESSION) }
}
