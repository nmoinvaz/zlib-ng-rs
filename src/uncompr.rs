//! uncompr.c -- decompress a memory buffer
//! Copyright (C) 1995-2026 Jean-loup Gailly, Mark Adler.
//! For conditions of distribution and use, see copyright notice in zlib.h

#[cfg(feature = "zlib-compat")]
use core::ffi::c_ulong;
use core::{mem, ptr};

use crate::inflate::{inflate, inflateEnd, inflateInit};
use crate::zbuild::{prefix, z_uintmax_t};
use crate::zlib::{
    Z_BUF_ERROR, Z_DATA_ERROR, Z_NEED_DICT, Z_NO_FLUSH, Z_OK, Z_STREAM_END, Z_STREAM_ERROR,
    z_stream,
};

/* ===========================================================================
     Decompresses the source buffer into the destination buffer.  *sourceLen is
   the byte length of the source buffer. Upon entry, *destLen is the total size
   of the destination buffer, which must be large enough to hold the entire
   uncompressed data. (The size of the uncompressed data must have been saved
   previously by the compressor and transmitted to the decompressor by some
   mechanism outside the scope of this compression library.) Upon exit,
   *destLen is the size of the decompressed data and *sourceLen is the number
   of source bytes consumed. Upon return, source + *sourceLen points to the
   first unused input byte.

     uncompress returns Z_OK if success, Z_MEM_ERROR if there was not enough
   memory, Z_BUF_ERROR if there was not enough room in the output buffer, or
   Z_DATA_ERROR if the input data was corrupted, including if the input data is
   an incomplete zlib stream.
*/
/// # Safety
///
/// `dest` must be valid for writes of `*dest_len` bytes and `source` must be valid for reads of
/// `*source_len` bytes. `dest_len` and `source_len` must each be null or valid for reads and writes.
#[cfg_attr(feature = "zlib-compat", unsafe(export_name = "uncompress2_z"))]
#[cfg_attr(not(feature = "zlib-compat"), unsafe(export_name = "zng_uncompress2"))]
pub unsafe extern "C" fn uncompress2_z(
    mut dest: *mut u8,
    dest_len: *mut usize,
    source: *const u8,
    source_len: *mut usize,
) -> i32 {
    const MAX: u32 = u32::MAX;
    let mut buf = [0u8; 1]; /* for detection of incomplete stream when *destLen == 0 */
    let buf = buf.as_mut_ptr();

    // SAFETY: the caller guarantees the lengths are null or valid, and that the buffers are valid for
    // the lengths given. The stream is only passed to inflate between inflateInit and inflateEnd.
    unsafe {
        if source_len.is_null()
            || (*source_len > 0 && source.is_null())
            || dest_len.is_null()
            || (*dest_len > 0 && dest.is_null())
        {
            return Z_STREAM_ERROR;
        }

        let mut len = *source_len;
        let mut left;
        if *dest_len != 0 {
            left = *dest_len;
            *dest_len = 0;
        } else {
            left = 1;
            dest = buf;
        }

        let mut stream: z_stream = mem::zeroed();
        stream.next_in = source;
        stream.avail_in = 0;
        stream.zalloc = None;
        stream.zfree = None;
        stream.opaque = ptr::null_mut();

        let mut err = inflateInit(&mut stream);
        if err != Z_OK {
            return err;
        }

        stream.next_out = dest;
        stream.avail_out = 0;

        loop {
            if stream.avail_out == 0 {
                stream.avail_out = if left > MAX as usize {
                    MAX
                } else {
                    left as u32
                };
                left -= stream.avail_out as usize;
            }
            if stream.avail_in == 0 {
                stream.avail_in = if len > MAX as usize { MAX } else { len as u32 };
                len -= stream.avail_in as usize;
            }
            err = inflate(&mut stream, Z_NO_FLUSH);
            if err != Z_OK {
                break;
            }
        }

        *source_len -= len + stream.avail_in as usize;
        if dest != buf {
            *dest_len = stream.total_out as usize;
        } else if stream.total_out != 0 && err == Z_BUF_ERROR {
            left = 1;
        }

        inflateEnd(&mut stream);
        if err == Z_STREAM_END {
            Z_OK
        } else if err == Z_NEED_DICT
            || (err == Z_BUF_ERROR && left + stream.avail_out as usize != 0)
        {
            Z_DATA_ERROR
        } else {
            err
        }
    }
}

/// # Safety
///
/// `dest` must be valid for writes of `*dest_len` bytes, `source` must be valid for reads of
/// `source_len` bytes, and `dest_len` must be null or valid for reads and writes.
#[unsafe(export_name = prefix!("uncompress"))]
pub unsafe extern "C" fn uncompress(
    dest: *mut u8,
    dest_len: *mut z_uintmax_t,
    source: *const u8,
    mut source_len: z_uintmax_t,
) -> i32 {
    // SAFETY: the caller upholds the contract of uncompress2 and source_len is a valid local.
    #[cfg(feature = "zlib-compat")]
    return unsafe { uncompress2(dest, dest_len, source, &mut source_len) };
    // SAFETY: the caller upholds the contract of uncompress2 and source_len is a valid local.
    #[cfg(not(feature = "zlib-compat"))]
    return unsafe { uncompress2_z(dest, dest_len, source, &mut source_len) };
}

/// # Safety
///
/// `dest` must be valid for writes of `*dest_len` bytes and `source` must be valid for reads of
/// `*source_len` bytes. `dest_len` and `source_len` must each be null or valid for reads and writes.
#[cfg(feature = "zlib-compat")]
#[unsafe(export_name = "uncompress2")]
pub unsafe extern "C" fn uncompress2(
    dest: *mut u8,
    dest_len: *mut c_ulong,
    source: *const u8,
    source_len: *mut c_ulong,
) -> i32 {
    // SAFETY: the caller guarantees the lengths are null or valid, and got and used are valid locals.
    unsafe {
        let mut got = if dest_len.is_null() {
            0
        } else {
            *dest_len as usize
        };
        let mut used = if source_len.is_null() {
            0
        } else {
            *source_len as usize
        };
        let ret = uncompress2_z(dest, &mut got, source, &mut used);
        if !source_len.is_null() {
            *source_len = used as c_ulong;
        }
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
#[unsafe(export_name = "uncompress_z")]
pub unsafe extern "C" fn uncompress_z(
    dest: *mut u8,
    dest_len: *mut usize,
    source: *const u8,
    mut source_len: usize,
) -> i32 {
    // SAFETY: the caller upholds the contract of uncompress2_z and source_len is a valid local.
    unsafe { uncompress2_z(dest, dest_len, source, &mut source_len) }
}
