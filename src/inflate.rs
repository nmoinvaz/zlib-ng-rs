//! inflate.h -- internal inflate state definition
//! Copyright (C) 1995-2019 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! inflate.c -- zlib decompression
//! Copyright (C) 1995-2026 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

/* WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change. Applications should only use zlib.h.
*/

#![allow(non_camel_case_types)]
// The widths of c_ulong, z_checksum_t and the bit count differ between targets and APIs.
#![allow(clippy::unnecessary_cast, clippy::useless_conversion)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;

#[cfg(feature = "s390-dfltcc-inflate")]
use crate::arch::s390::dfltcc_inflate;
use crate::crc32::crc32_small;
use crate::crc32_braid_tbl::CRC_TABLE;
use crate::functable;
use crate::inffixed_tbl::{DISTFIX, LENFIX};
use crate::inflate_p::{
    INFLATE_FAST_MIN_HAVE, INFLATE_FAST_MIN_LEFT, INFLATE_FAST_MIN_SAFE, bits_t, chunkcopy_safe,
    code_bits, code_extra, set_bad,
};
use crate::inftrees::{CODES, DISTS, ENOUGH, LENS, code, zng_inflate_table};
use crate::zbuild::{likely, pad_16, pad_64, padsz, prefix, z_checksum_t, z_uintmax_t};
use crate::zconf::{MAX_WBITS, MIN_WBITS};
#[cfg(feature = "zlib-compat")]
use crate::zlib::ZLIB_VERSION;
use crate::zlib::{
    Z_BLOCK, Z_BUF_ERROR, Z_DATA_ERROR, Z_DEFLATED, Z_FINISH, Z_MEM_ERROR, Z_NEED_DICT, Z_OK,
    Z_STREAM_END, Z_STREAM_ERROR, Z_TREES, Z_VERSION_ERROR, free_func, gz_header, internal_state,
    z_stream,
};
use crate::zutil::{
    ADLER32_INITIAL_VALUE, CRC32_INITIAL_VALUE, DEF_WBITS, MAX_LEN_ROOT_BITS, PKZIP_BUG_WORKAROUND,
    check_ver_stsize, zcalloc, zcfree,
};

/// Possible inflate modes between inflate() calls. The C sources store them in the state, so
/// this is a plain integer that can hold any value they write.
pub(crate) type inflate_mode = c_uint;

/// i: waiting for magic header
pub(crate) const HEAD: inflate_mode = 16180;
/// i: waiting for method and flags (gzip)
pub(crate) const FLAGS: inflate_mode = 16181;
/// i: waiting for modification time (gzip)
pub(crate) const TIME: inflate_mode = 16182;
/// i: waiting for extra flags and operating system (gzip)
pub(crate) const OS: inflate_mode = 16183;
/// i: waiting for extra length (gzip)
pub(crate) const EXLEN: inflate_mode = 16184;
/// i: waiting for extra bytes (gzip)
pub(crate) const EXTRA: inflate_mode = 16185;
/// i: waiting for end of file name (gzip)
pub(crate) const NAME: inflate_mode = 16186;
/// i: waiting for end of comment (gzip)
pub(crate) const COMMENT: inflate_mode = 16187;
/// i: waiting for header crc (gzip)
pub(crate) const HCRC: inflate_mode = 16188;
/// i: waiting for dictionary check value
pub(crate) const DICTID: inflate_mode = 16189;
/// waiting for inflateSetDictionary() call
pub(crate) const DICT: inflate_mode = 16190;
/// i: waiting for type bits, including last-flag bit
pub(crate) const TYPE: inflate_mode = 16191;
/// i: same, but skip check to exit inflate on new block
pub(crate) const TYPEDO: inflate_mode = 16192;
/// i: waiting for stored size (length and complement)
pub(crate) const STORED: inflate_mode = 16193;
/// i/o: same as COPY below, but only first time in
pub(crate) const COPY_: inflate_mode = 16194;
/// i/o: waiting for input or output to copy stored block
pub(crate) const COPY: inflate_mode = 16195;
/// i: waiting for dynamic block table lengths
pub(crate) const TABLE: inflate_mode = 16196;
/// i: waiting for code length code lengths
pub(crate) const LENLENS: inflate_mode = 16197;
/// i: waiting for length/lit and distance code lengths
pub(crate) const CODELENS: inflate_mode = 16198;
/// i: same as LEN below, but only first time in
pub(crate) const LEN_: inflate_mode = 16199;
/// i: waiting for length/lit/eob code
pub(crate) const LEN: inflate_mode = 16200;
/// i: waiting for length extra bits
pub(crate) const LENEXT: inflate_mode = 16201;
/// i: waiting for distance code
pub(crate) const DIST: inflate_mode = 16202;
/// i: waiting for distance extra bits
pub(crate) const DISTEXT: inflate_mode = 16203;
/// o: waiting for output space to copy string
pub(crate) const MATCH: inflate_mode = 16204;
/// o: waiting for output space to write literal
pub(crate) const LIT: inflate_mode = 16205;
/// i: waiting for 32-bit check value
pub(crate) const CHECK: inflate_mode = 16206;
/// i: waiting for 32-bit length (gzip)
pub(crate) const LENGTH: inflate_mode = 16207;
/// finished check, done -- remain here until reset
pub(crate) const DONE: inflate_mode = 16208;
/// got a data error -- remain here until reset
pub(crate) const BAD: inflate_mode = 16209;
/// looking for synchronization bytes to restart inflate()
pub(crate) const SYNC: inflate_mode = 16210;

/*
   State transitions between above modes -

   (most modes can go to BAD on error -- not shown for clarity)

   Process header:
       HEAD -> (gzip) or (zlib) or (raw)
       (gzip) -> FLAGS -> TIME -> OS -> EXLEN -> EXTRA -> NAME -> COMMENT ->
                 HCRC -> TYPE
       (zlib) -> DICTID or TYPE
       DICTID -> DICT -> TYPE
       (raw) -> TYPEDO
   Read deflate blocks:
           TYPE -> TYPEDO -> STORED or TABLE or LEN_ or CHECK
           STORED -> COPY_ -> COPY -> TYPE
           TABLE -> LENLENS -> CODELENS -> LEN_
           LEN_ -> LEN
   Read deflate codes in fixed or dynamic block:
               LEN -> LENEXT or LIT or TYPE
               LENEXT -> DIST -> DISTEXT -> MATCH -> LEN
               LIT -> LEN
   Process trailer:
       CHECK -> LENGTH -> DONE
*/

/// Struct for memory allocation handling
#[repr(C)]
pub(crate) struct inflate_allocs {
    pub(crate) buf_start: *mut u8,
    pub(crate) zfree: free_func,
    pub(crate) state: *mut inflate_state,
    pub(crate) window: *mut u8,
}

/// State maintained between inflate() calls -- approximately 7K bytes, not
/// including the allocated sliding window, which is up to 32K bytes.
///
/// The C sources own the structure and end it with fields that depend on the architecture. This
/// mirrors the fields ahead of those, and the build checks every offset against C.
#[repr(C)]
pub(crate) struct inflate_state {
    /// pointer back to this zlib stream
    pub(crate) strm: *mut z_stream,
    /// current inflate mode
    pub(crate) mode: inflate_mode,
    /// true if processing last block
    pub(crate) last: c_int,
    /// bit 0 true for zlib, bit 1 true for gzip, bit 2 true to validate check value
    pub(crate) wrap: c_int,
    /// true if dictionary provided
    pub(crate) havedict: c_int,
    /// gzip header method and flags, 0 if zlib, or -1 if raw or no header yet
    pub(crate) flags: c_int,
    /// initial length of match, for inflateMark
    pub(crate) was: c_uint,
    /// protected copy of check value
    pub(crate) check: c_ulong,
    /// protected copy of output count
    pub(crate) total: c_ulong,
    /// where to save gzip header information
    pub(crate) head: *mut gz_header,
    /// bits back of last unprocessed length/lit
    pub(crate) back: c_int,

    /* sliding window */
    /// log base 2 of requested window size
    pub(crate) wbits: c_uint,
    /// window size or zero if not using window
    pub(crate) wsize: u32,
    /// real size of the allocated window buffer, including padding
    pub(crate) wbufsize: u32,
    /// valid bytes in the window
    pub(crate) whave: u32,
    /// window write index
    pub(crate) wnext: u32,
    /// allocated sliding window, if needed
    pub(crate) window: *mut u8,

    /* bit accumulator */
    /// input bit accumulator
    pub(crate) hold: u64,
    /// number of bits in hold
    pub(crate) bits: c_uint,
    /* fixed and dynamic code tables */
    /// index bits for lencode
    pub(crate) lenbits: c_uint,
    /// starting table for length/literal codes
    pub(crate) lencode: *const code,
    /// starting table for distance codes
    pub(crate) distcode: *const code,
    /// index bits for distcode
    pub(crate) distbits: c_uint,
    /* for string and stored block copying */
    /// literal or length of data to copy
    pub(crate) length: u32,
    /// distance back to copy string from
    pub(crate) offset: c_uint,
    /* for table and code decoding */
    /// extra bits needed
    pub(crate) extra: c_uint,
    /* dynamic table building */
    /// number of code length code lengths
    pub(crate) ncode: c_uint,
    /// number of length code lengths
    pub(crate) nlen: c_uint,
    /// number of distance code lengths
    pub(crate) ndist: c_uint,
    /// number of code lengths in lens[]
    pub(crate) have: u32,
    /// next available space in codes[]
    pub(crate) next: *mut code,

    /// temporary storage for code lengths
    pub(crate) lens: [u16; 320],
    /// work area for code table building
    pub(crate) work: [u16; 288],
    /// space for code tables
    pub(crate) codes: [code; ENOUGH],

    /// struct for handling memory allocations
    pub(crate) alloc_bufs: *mut inflate_allocs,

    /// zlib header max distance (INFLATE_STRICT)
    #[cfg(feature = "inflate-strict")]
    pub(crate) dmax: c_uint,
    /// if false, allow invalid distance too far
    #[cfg(feature = "inflate-allow-invalid-dist")]
    pub(crate) sane: c_int,
}

/// The size of the whole C structure, which ends with fields that depend on the architecture
#[cfg(feature = "c-layout")]
use crate::c_layout::INFLATE_STATE_SIZE;
/// The size for a plain cargo build, which has no C sources to ask.
#[cfg(not(feature = "c-layout"))]
const INFLATE_STATE_SIZE: usize = size_of::<inflate_state>().next_multiple_of(64);

/* ===========================================================================
 *  Architecture-specific hooks.
 */
/* DFLTCC instructions require window to be page-aligned */
#[cfg(feature = "s390-dfltcc-inflate")]
pub(crate) const WINDOW_PAD_SIZE: usize = 4096;
#[cfg(not(feature = "s390-dfltcc-inflate"))]
pub(crate) const WINDOW_PAD_SIZE: usize = 64;

#[cfg(feature = "s390-dfltcc-inflate")]
const HB_SIZE: usize = 1 << 15;

#[inline(always)]
const fn pad_window(bpos: usize) -> usize {
    bpos + padsz(bpos, WINDOW_PAD_SIZE)
}

/// Adjust the window size for the arch-specific inflate code.
#[inline(always)]
const fn inflate_adjust_window_size(n: usize) -> usize {
    #[cfg(feature = "s390-dfltcc-inflate")]
    return if n > HB_SIZE { n } else { HB_SIZE };
    #[cfg(not(feature = "s390-dfltcc-inflate"))]
    return n;
}

/// Returns whether zlib-ng should compute a checksum. Set to 0 if arch-specific inflation code
/// already does that.
///
/// # Safety
///
/// `strm` must be a valid inflate stream.
#[inline(always)]
unsafe fn inflate_need_checksum(_strm: *mut z_stream) -> bool {
    // SAFETY: the caller guarantees the stream is valid.
    #[cfg(feature = "s390-dfltcc-inflate")]
    return unsafe { dfltcc_inflate::dfltcc_can_inflate(_strm) == 0 };
    #[cfg(not(feature = "s390-dfltcc-inflate"))]
    return true;
}

/// Returns whether zlib-ng should update a window. Set to 0 if arch-specific inflation code
/// already does that.
///
/// # Safety
///
/// `strm` must be a valid inflate stream.
#[inline(always)]
unsafe fn inflate_need_updatewindow(_strm: *mut z_stream) -> bool {
    // SAFETY: the caller guarantees the stream is valid.
    #[cfg(feature = "s390-dfltcc-inflate")]
    return unsafe { dfltcc_inflate::dfltcc_can_inflate(_strm) == 0 };
    #[cfg(not(feature = "s390-dfltcc-inflate"))]
    return true;
}

/* ===========================================================================
 *  The functions of inflate.c
 */

/// # Safety
///
/// `strm` must be a valid inflate stream, `src` valid for reads and `dst` for writes of `copy`
/// bytes.
#[inline]
unsafe fn inf_chksum_cpy(strm: *mut z_stream, dst: *mut u8, src: *const u8, copy: u32) {
    if copy == 0 {
        return;
    }
    // SAFETY: the caller guarantees the stream and both buffers.
    unsafe {
        let state = (*strm).state.cast::<inflate_state>();
        let check = if (*state).flags != 0 {
            functable::crc32_copy((*state).check as u32, dst, src, copy as usize)
        } else {
            functable::adler32_copy((*state).check as u32, dst, src, copy as usize)
        };
        (*state).check = c_ulong::from(check);
        (*strm).adler = z_checksum_t::from(check);
    }
}

/// # Safety
///
/// `strm` must be a valid inflate stream and `src` valid for reads of `len` bytes.
#[inline]
unsafe fn inf_chksum(strm: *mut z_stream, src: *const u8, len: u32) {
    // SAFETY: the caller guarantees the stream and the buffer.
    unsafe {
        let state = (*strm).state.cast::<inflate_state>();
        let check = if (*state).flags != 0 {
            functable::crc32((*state).check as u32, src, len as usize)
        } else {
            functable::adler32((*state).check as u32, src, len as usize)
        };
        (*state).check = c_ulong::from(check);
        (*strm).adler = z_checksum_t::from(check);
    }
}

/// Whether the stream is no usable inflate stream
///
/// # Safety
///
/// `strm` must be null or valid for reads, with a state that is null or valid for reads.
#[allow(non_snake_case)]
unsafe fn inflateStateCheck(strm: *mut z_stream) -> bool {
    // SAFETY: the caller guarantees the stream and its state are null or readable.
    unsafe {
        if strm.is_null() || (*strm).zalloc.is_none() || (*strm).zfree.is_none() {
            return true;
        }
        let state = (*strm).state.cast::<inflate_state>();
        state.is_null()
            || (*state).alloc_bufs.is_null()
            || (*state).strm != strm
            || (*state).mode < HEAD
            || (*state).mode > SYNC
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflateResetKeep"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateResetKeep(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        (*strm).total_in = 0;
        (*strm).total_out = 0;
        (*state).total = 0;
        (*strm).msg = ptr::null();
        (*strm).data_type = 0;
        if (*state).wrap != 0 {
            /* to support ill-conceived Java test suite */
            (*strm).adler = ((*state).wrap & 1) as z_checksum_t;
        }
        (*state).mode = HEAD;
        (*state).check = c_ulong::from(ADLER32_INITIAL_VALUE);
        (*state).last = 0;
        (*state).havedict = 0;
        (*state).flags = -1;
        (*state).head = ptr::null_mut();
        (*state).hold = 0;
        (*state).bits = 0;
        let codes = (&raw mut (*state).codes).cast::<code>();
        (*state).lencode = codes;
        (*state).distcode = codes;
        (*state).next = codes;
        (*state).back = -1;
        #[cfg(feature = "inflate-strict")]
        {
            (*state).dmax = 32768;
        }
        #[cfg(feature = "inflate-allow-invalid-dist")]
        {
            (*state).sane = 1;
        }
        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-inflate")]
        dfltcc_inflate::dfltcc_reset_inflate_state(strm);
        Z_OK
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflateReset"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateReset(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        (*state).wsize = 0;
        (*state).whave = 0;
        (*state).wnext = 0;
        inflateResetKeep(strm)
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflateReset2"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateReset2(strm: *mut z_stream, mut windowBits: i32) -> i32 {
    let wrap;

    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        /* get the state */
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();

        /* extract wrap request from windowBits parameter */
        if windowBits < 0 {
            wrap = 0;
            if windowBits < -MAX_WBITS {
                return Z_STREAM_ERROR;
            }
            windowBits = -windowBits;
        } else {
            wrap = (windowBits >> 4) + 5;
            if windowBits < 48 {
                windowBits &= MAX_WBITS;
            }
        }

        /* set number of window bits */
        if windowBits != 0 && !(MIN_WBITS..=MAX_WBITS).contains(&windowBits) {
            return Z_STREAM_ERROR;
        }

        /* update state and reset the rest of it */
        (*state).wrap = wrap;
        (*state).wbits = windowBits as c_uint;
        inflateReset(strm)
    }
}

/* ===========================================================================
 * Allocate a big buffer and divide it up into the various buffers inflate needs.
 * Handles alignment of allocated buffer and alignment of individual buffers.
 */
/// # Safety
///
/// `strm` must be valid, and its zalloc must hand out memory that it may use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn alloc_inflate(strm: *mut z_stream) -> *mut inflate_allocs {
    let mut curr_size = 0;

    /* Define sizes */
    let window_size = inflate_adjust_window_size((1 << MAX_WBITS) + 64); /* 64B padding for chunksize */
    let state_size = INFLATE_STATE_SIZE;
    let alloc_size = size_of::<inflate_allocs>();

    /* Calculate relative buffer positions and paddings */
    let window_pos = pad_window(curr_size);
    curr_size = window_pos + window_size;

    let state_pos = pad_64(curr_size);
    curr_size = state_pos + state_size;

    let alloc_pos = pad_16(curr_size);
    curr_size = alloc_pos + alloc_size;

    /* Add 64-1 or 4096-1 to allow window alignment, and round size of buffer up to multiple of 64 */
    let total_size = pad_64(curr_size + (WINDOW_PAD_SIZE - 1));

    // SAFETY: the caller guarantees the stream and its allocator are valid. Every buffer below
    // lies inside the total_size bytes that the allocator handed out.
    unsafe {
        /* Allocate buffer, align to 64-byte cacheline, and zerofill the resulting buffer */
        let Some(zalloc) = (*strm).zalloc else {
            return ptr::null_mut();
        };
        let original_buf = zalloc((*strm).opaque, 1, total_size as c_uint).cast::<u8>();
        if original_buf.is_null() {
            return ptr::null_mut();
        }

        let buff = original_buf.add(padsz(original_buf.addr(), WINDOW_PAD_SIZE));

        /* Initialize alloc_bufs */
        let alloc_bufs = buff.add(alloc_pos).cast::<inflate_allocs>();
        (*alloc_bufs).buf_start = original_buf;
        (*alloc_bufs).zfree = (*strm).zfree;

        (*alloc_bufs).window = buff.add(window_pos);
        (*alloc_bufs).state = buff.add(state_pos).cast::<inflate_state>();

        alloc_bufs
    }
}

/* ===========================================================================
 * Free all allocated inflate buffers
 */
/// # Safety
///
/// `strm` must be a valid inflate stream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_inflate(strm: *mut z_stream) {
    // SAFETY: the caller guarantees the stream and its state are valid.
    unsafe {
        let state = (*strm).state.cast::<inflate_state>();

        if !(*state).alloc_bufs.is_null() {
            let alloc_bufs = (*state).alloc_bufs;
            if let Some(zfree) = (*alloc_bufs).zfree {
                zfree((*strm).opaque, (*alloc_bufs).buf_start.cast::<c_void>());
            }
            (*strm).state = ptr::null_mut();
        }
    }
}

/* ===========================================================================
 * Initialize inflate state and buffers.
 * This function is hidden in ZLIB_COMPAT builds.
 */
/// # Safety
///
/// `strm` must be null or valid for reads and writes, with zalloc, zfree and opaque set up or
/// null.
#[cfg_attr(not(feature = "zlib-compat"), unsafe(export_name = "zng_inflateInit2"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateInit2(strm: *mut z_stream, windowBits: i32) -> i32 {
    /* Initialize functable */
    if functable::force_init_failed() {
        return Z_VERSION_ERROR;
    }

    if strm.is_null() {
        return Z_STREAM_ERROR;
    }
    // SAFETY: the caller guarantees the stream. The allocation holds the state and the window.
    unsafe {
        (*strm).msg = ptr::null(); /* in case we return an error */
        if (*strm).zalloc.is_none() {
            (*strm).zalloc = Some(zcalloc);
            (*strm).opaque = ptr::null_mut();
        }
        if (*strm).zfree.is_none() {
            (*strm).zfree = Some(zcfree);
        }

        let alloc_bufs = alloc_inflate(strm);
        if alloc_bufs.is_null() {
            return Z_MEM_ERROR;
        }

        let state = (*alloc_bufs).state;
        (*state).window = (*alloc_bufs).window;
        (*state).alloc_bufs = alloc_bufs;
        (*state).wbufsize = inflate_adjust_window_size((1 << MAX_WBITS) + 64) as u32;

        (*strm).state = state.cast::<internal_state>();
        (*state).strm = strm;
        (*state).mode = HEAD; /* to pass state test in inflateReset2() */
        let ret = inflateReset2(strm, windowBits);
        if ret != Z_OK {
            free_inflate(strm);
        }
        ret
    }
}

/// # Safety
///
/// `strm` must be null or valid for reads and writes, with zalloc, zfree and opaque set up or
/// null.
#[cfg(not(feature = "zlib-compat"))]
#[unsafe(export_name = "zng_inflateInit")]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateInit(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller upholds the contract of inflateInit2.
    unsafe { inflateInit2(strm, DEF_WBITS) }
}

/// inflateInit is a macro in zlib.h to allow checking the zlib version
/// and the compiler's view of z_stream
///
/// # Safety
///
/// `strm` must be valid for reads and writes.
#[cfg(feature = "zlib-compat")]
#[allow(non_snake_case)]
#[inline]
pub(crate) unsafe fn inflateInit(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees strm is valid and the version is a NUL terminated string.
    unsafe { inflateInit_(strm, ZLIB_VERSION.as_ptr(), size_of::<z_stream>() as i32) }
}

/* Function used by zlib.h and zlib-ng version 2.0 macros */
/// # Safety
///
/// `strm` must be null or valid for reads and writes, and `version` must be null or point to a
/// string.
#[unsafe(export_name = prefix!("inflateInit_"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateInit_(
    strm: *mut z_stream,
    version: *const c_char,
    stream_size: i32,
) -> i32 {
    // SAFETY: the caller upholds the contracts of check_ver_stsize and inflateInit2.
    unsafe {
        if check_ver_stsize(version, stream_size) {
            return Z_VERSION_ERROR;
        }
        inflateInit2(strm, DEF_WBITS)
    }
}

/* Function used by zlib.h and zlib-ng version 2.0 macros */
/// # Safety
///
/// `strm` must be null or valid for reads and writes, and `version` must be null or point to a
/// string.
#[unsafe(export_name = prefix!("inflateInit2_"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateInit2_(
    strm: *mut z_stream,
    windowBits: i32,
    version: *const c_char,
    stream_size: i32,
) -> i32 {
    // SAFETY: the caller upholds the contracts of check_ver_stsize and inflateInit2.
    unsafe {
        if check_ver_stsize(version, stream_size) {
            return Z_VERSION_ERROR;
        }
        inflateInit2(strm, windowBits)
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflatePrime"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflatePrime(strm: *mut z_stream, bits: i32, mut value: i32) -> i32 {
    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        if bits == 0 {
            return Z_OK;
        }
        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-inflate")]
        if dfltcc_inflate::dfltcc_inflate_disable(strm) != 0 {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        if bits < 0 {
            (*state).hold = 0;
            (*state).bits = 0;
            return Z_OK;
        }
        if bits > 16 || (*state).bits.wrapping_add(bits as c_uint) > 32 {
            return Z_STREAM_ERROR;
        }
        value &= (1 << bits) - 1;
        (*state).hold = (*state).hold.wrapping_add((value as u64) << (*state).bits);
        (*state).bits += bits as c_uint;
        Z_OK
    }
}

/*
  Return state with length and distance decoding tables and index sizes set to
  fixed code decoding.  This returns fixed tables from inffixed_tbl.h.
*/
/// # Safety
///
/// `state` must be valid for writes.
#[unsafe(export_name = prefix!("fixedtables"))]
pub unsafe extern "C" fn fixedtables(state: *mut inflate_state) {
    // SAFETY: the caller guarantees the state.
    unsafe {
        (*state).lencode = LENFIX.as_ptr();
        (*state).lenbits = 9;
        (*state).distcode = DISTFIX.as_ptr();
        (*state).distbits = 5;
    }
}

/*
  Update the window with the last wsize (normally 32K) bytes written before
  returning.  If window does not exist yet, create it.  This is only called
  when a window is already in use, or when output has been written during this
  inflate call, but the end of the deflate stream has not been reached yet.
  It is also called to create a window for dictionary data when a dictionary
  is loaded.

  Providing output buffers larger than 32K to inflate() should provide a speed
  advantage, since only the last 32K of output is copied to the sliding window
  upon return from inflate(), and since all distances after the first 32K of
  output will fall in the output data, making match copies simpler and faster.
  The advantage may be dependent on the size of the processor's data caches.
*/
/// # Safety
///
/// `strm` must be a valid inflate stream, and the `len` bytes ahead of `end` valid for reads.
unsafe fn updatewindow(strm: *mut z_stream, end: *const u8, mut len: u32, cksum: i32) {
    // SAFETY: the caller guarantees the stream and the bytes ahead of end. The window holds
    // wsize bytes, and wnext stays below wsize.
    unsafe {
        let state = (*strm).state.cast::<inflate_state>();

        /* if window not in use yet, initialize */
        if (*state).wsize == 0 {
            (*state).wsize = 1 << (*state).wbits;
        }
        let wsize = (*state).wsize;
        let window = (*state).window;

        /* len state->wsize or less output bytes into the circular window */
        if len >= wsize {
            /* Only do this if the caller specifies to checksum bytes AND the platform requires
             * it (s/390 being the primary exception to this) */
            if inflate_need_checksum(strm) && cksum != 0 {
                /* We have to split the checksum over non-copied and copied bytes */
                if len > wsize {
                    inf_chksum(strm, end.wrapping_sub(len as usize), len - wsize);
                }
                inf_chksum_cpy(strm, window, end.wrapping_sub(wsize as usize), wsize);
            } else {
                ptr::copy_nonoverlapping(end.wrapping_sub(wsize as usize), window, wsize as usize);
            }

            (*state).wnext = 0;
            (*state).whave = wsize;
        } else {
            let wnext = (*state).wnext;
            let mut dist = wsize - wnext;
            /* Only do this if the caller specifies to checksum bytes AND the platform requires
             * We need to maintain the correct order here for the checksum */
            dist = dist.min(len);
            let src = end.wrapping_sub(len as usize);
            if inflate_need_checksum(strm) && cksum != 0 {
                inf_chksum_cpy(strm, window.add(wnext as usize), src, dist);
            } else {
                ptr::copy_nonoverlapping(src, window.add(wnext as usize), dist as usize);
            }
            len -= dist;
            if len != 0 {
                let src = end.wrapping_sub(len as usize);
                if inflate_need_checksum(strm) && cksum != 0 {
                    inf_chksum_cpy(strm, window, src, len);
                } else {
                    ptr::copy_nonoverlapping(src, window, len as usize);
                }

                (*state).wnext = len;
                (*state).whave = wsize;
            } else {
                (*state).wnext = wnext + dist;
                if (*state).wnext == wsize {
                    (*state).wnext = 0;
                }
                if (*state).whave < wsize {
                    (*state).whave += dist;
                }
            }
        }
    }
}

/* check macros for header crc */
#[inline(always)]
fn crc_do1_b(c: u32, b: u64) -> u32 {
    CRC_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8)
}

#[inline(always)]
fn crc2(check: c_ulong, word: u64) -> c_ulong {
    let mut crc = !(check as u32);
    crc = crc_do1_b(crc, word);
    crc = crc_do1_b(crc, word >> 8);
    c_ulong::from(!crc)
}

#[inline(always)]
fn crc4(check: c_ulong, word: u64) -> c_ulong {
    let mut crc = !(check as u32);
    crc = crc_do1_b(crc, word);
    crc = crc_do1_b(crc, word >> 8);
    crc = crc_do1_b(crc, word >> 16);
    crc = crc_do1_b(crc, word >> 24);
    c_ulong::from(!crc)
}

/*
  inflate() uses a state machine to process as much input data and generate as
  much output data as possible before returning.  The state machine is
  structured roughly as follows:

   for (;;) switch (state) {
   ...
   case STATEn:
       if (not enough input data or output space to make progress)
           return;
       ... make progress ...
       state = STATEm;
       break;
   ...
   }

  so when inflate() is called again, the same case is attempted again, and
  if the appropriate resources are provided, the machine proceeds to the
  next state.  The NEEDBITS() macro is usually the way the state evaluates
  whether it can proceed or should return.  NEEDBITS() does the return if
  the requested bits are not available.  The typical use of the BITS macros
  is:

       NEEDBITS(n);
       ... do something with BITS(n) ...
       DROPBITS(n);

  where NEEDBITS(n) either returns from inflate() if there isn't enough
  input left to load n bits into the accumulator, or it continues.  BITS(n)
  gives the low n bits in the accumulator.  When done, DROPBITS(n) drops
  the low n bits off the accumulator.  INITBITS() clears the accumulator
  and sets the number of available bits to zero.  BYTEBITS() discards just
  enough bits to put the accumulator on a byte boundary.  After BYTEBITS()
  and a NEEDBITS(8), then BITS(8) would return the next byte in the stream.

  NEEDBITS(n) uses PULLBYTE() to get an available byte of input, or to return
  if there is no input available.  The decoding of variable length codes uses
  PULLBYTE() directly in order to pull just enough bytes to decode the next
  code, and no more.

  Some states loop until they get enough input, making sure that enough
  state information is maintained to continue the loop where it left off
  if NEEDBITS() returns in the loop.  For example, want, need, and keep
  would all have to actually be part of the saved state in case NEEDBITS()
  returns:

   case STATEw:
       while (want < need) {
           NEEDBITS(n);
           keep[want++] = BITS(n);
           DROPBITS(n);
       }
       state = STATEx;
   case STATEx:

  As shown above, if the next state is also the next case, then the break
  is omitted.

  A state may also return if there is not enough output space available to
  complete that state.  Those states are copying stored data, writing a
  literal byte, and copying a matching string.

  When returning, a "goto inf_leave" is used to update the total counters,
  update the check value, and determine whether any progress has been made
  during that inflate() call in order to return the proper return code.
  Progress is defined as a change in either strm->avail_in or strm->avail_out.
  When there is a window, goto inf_leave will update the window with the last
  output written.  If a goto inf_leave occurs in the middle of decompression
  and there is no window currently, goto inf_leave will create one and copy
  output to the window for the next call of inflate().

  In this implementation, the flush parameter of inflate() only affects the
  return code (per zlib.h).  inflate() always writes as much as possible to
  strm->next_out, given the space available and the provided input--the effect
  documented in zlib.h of Z_SYNC_FLUSH.  Furthermore, inflate() always defers
  the allocation of and copying into a sliding window until necessary, which
  provides the effect documented in zlib.h for Z_FINISH when the entire input
  stream available.  So the only thing the flush parameter actually does is:
  when flush is set to Z_FINISH, inflate() cannot return Z_OK.  Instead it
  will return Z_BUF_ERROR if it has not reached the end of the stream.
*/
// Rust has no fall through from one case to the next. A state that C falls out of stores the
// next mode and loops, which lands in that state. The states of one match fall through for
// real, in nested blocks, because the loop would cost a dispatch for each of them.
/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up, with next_in valid for reads of
/// avail_in bytes and next_out valid for writes of avail_out bytes.
#[unsafe(export_name = prefix!("inflate"))]
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
pub unsafe extern "C" fn inflate(strm: *mut z_stream, flush: i32) -> i32 {
    /* permutation of code lengths */
    static ORDER: [u16; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    // SAFETY: the caller guarantees the stream and its buffers, and inflateStateCheck vouches
    // for the state. have and left count the bytes that remain at next and put, and no input
    // is read or output written beyond them. The tables hold every entry that an index of
    // lenbits or distbits bits or a table link can reach.
    unsafe {
        if inflateStateCheck(strm)
            || (*strm).next_out.is_null()
            || ((*strm).next_in.is_null() && (*strm).avail_in != 0)
        {
            return Z_STREAM_ERROR;
        }

        let state = (*strm).state.cast::<inflate_state>();
        if (*state).mode == TYPE {
            /* skip check */
            (*state).mode = TYPEDO;
        }

        /* next input */
        let mut next: *const u8;
        /* next output */
        let mut put: *mut u8;
        /* available input and output */
        let mut have: u32;
        let mut left: u32;
        /* bit buffer */
        let mut hold: u64;
        /* bits in bit buffer */
        let mut bits: bits_t;
        /* save starting available input and output */
        let mut input: u32;
        let mut out: u32;
        /* number of stored or match bytes to copy */
        let mut copy: u32;
        /* current decoding table entry */
        let mut here: code;
        /* parent table entry */
        let mut last: code;
        /* length to copy for repeats, bits to drop */
        let mut len: u32;
        /* return code */
        let mut ret: i32;

        /* Load registers with state in inflate() for speed */
        macro_rules! load {
            () => {
                put = (*strm).next_out;
                left = (*strm).avail_out;
                next = (*strm).next_in;
                have = (*strm).avail_in;
                hold = (*state).hold;
                bits = (*state).bits as bits_t;
            };
        }
        /* Restore state from registers in inflate() */
        macro_rules! restore {
            () => {
                (*strm).next_out = put;
                (*strm).avail_out = left;
                (*strm).next_in = next;
                (*strm).avail_in = have;
                (*state).hold = hold;
                (*state).bits = u32::from(bits);
            };
        }
        /* Clear the input bit accumulator */
        macro_rules! initbits {
            () => {
                hold = 0;
                bits = 0;
            };
        }
        /* Return the low n bits of the bit accumulator (n < 16) */
        macro_rules! bits {
            ($n:expr) => {
                (hold as u32) & ((1u32 << ($n)) - 1)
            };
        }
        /* Remove n bits from the bit accumulator */
        macro_rules! dropbits {
            ($n:expr) => {
                let n = $n as u32;
                hold >>= n;
                bits = bits.wrapping_sub(n as bits_t);
            };
        }
        /* Remove zero to seven bits as needed to go to a byte boundary */
        macro_rules! bytebits {
            () => {
                hold >>= bits & 7;
                bits -= bits & 7;
            };
        }
        /* Set mode=BAD and prepare error message */
        macro_rules! bad {
            ($msg:expr) => {
                set_bad(strm, state, $msg)
            };
        }

        load!();
        input = have;
        out = left;
        ret = Z_OK;
        'machine: loop {
            // These two leave the loop, and a macro only sees a label that is in scope where it
            // is defined.
            /* Get a byte of input into the bit accumulator, or return from inflate() if there is no input available. */
            macro_rules! pullbyte {
                () => {
                    if have == 0 {
                        break 'machine;
                    }
                    have -= 1;
                    hold = hold.wrapping_add(u64::from(*next) << bits);
                    next = next.add(1);
                    bits += 8;
                };
            }
            /* Ensure that there is at least n bits in the bit accumulator.  If there is
            not enough available input to do that, then return from inflate()/inflateBack(). */
            macro_rules! needbits {
                ($n:expr) => {
                    let n = $n as u32;
                    while u32::from(bits) < n {
                        pullbyte!();
                    }
                };
            }

            let mode = (*state).mode;
            match mode {
                HEAD => {
                    if (*state).wrap == 0 {
                        (*state).mode = TYPEDO;
                        continue;
                    }
                    needbits!(16);
                    if ((*state).wrap & 2) != 0 && hold == 0x8b1f {
                        /* gzip header */
                        if (*state).wbits == 0 {
                            (*state).wbits = MAX_WBITS as c_uint;
                        }
                        (*state).check = c_ulong::from(CRC32_INITIAL_VALUE);
                        (*state).check = crc2((*state).check, hold);
                        initbits!();
                        (*state).mode = FLAGS;
                        continue;
                    }
                    if !(*state).head.is_null() {
                        (*(*state).head).done = -1;
                    }
                    /* check if zlib header allowed */
                    if ((*state).wrap & 1) == 0
                        || !(((hold & 0xff) << 8) + (hold >> 8)).is_multiple_of(31)
                    {
                        bad!(c"incorrect header check");
                        continue;
                    }
                    if bits!(4) != Z_DEFLATED as u32 {
                        bad!(c"unknown compression method");
                        continue;
                    }
                    dropbits!(4);
                    len = bits!(4) + 8;
                    if (*state).wbits == 0 {
                        (*state).wbits = len;
                    }
                    if len > MAX_WBITS as u32 || len > (*state).wbits {
                        bad!(c"invalid window size");
                        continue;
                    }
                    #[cfg(feature = "inflate-strict")]
                    {
                        (*state).dmax = 1 << len;
                    }
                    /* indicate zlib header */
                    (*state).flags = 0;
                    (*state).check = c_ulong::from(ADLER32_INITIAL_VALUE);
                    (*strm).adler = z_checksum_t::from(ADLER32_INITIAL_VALUE);
                    (*state).mode = if hold & 0x200 != 0 { DICTID } else { TYPE };
                    initbits!();
                }

                FLAGS => {
                    needbits!(16);
                    (*state).flags = hold as c_int;
                    if ((*state).flags & 0xff) != Z_DEFLATED {
                        bad!(c"unknown compression method");
                        continue;
                    }
                    if (*state).flags & 0xe000 != 0 {
                        bad!(c"unknown header flags set");
                        continue;
                    }
                    if !(*state).head.is_null() {
                        (*(*state).head).text = ((hold >> 8) & 1) as c_int;
                    }
                    if ((*state).flags & 0x0200) != 0 && ((*state).wrap & 4) != 0 {
                        (*state).check = crc2((*state).check, hold);
                    }
                    initbits!();
                    (*state).mode = TIME;
                }

                TIME => {
                    needbits!(32);
                    if !(*state).head.is_null() {
                        (*(*state).head).time = c_ulong::from(hold as u32);
                    }
                    if ((*state).flags & 0x0200) != 0 && ((*state).wrap & 4) != 0 {
                        (*state).check = crc4((*state).check, hold);
                    }
                    initbits!();
                    (*state).mode = OS;
                }

                OS => {
                    needbits!(16);
                    if !(*state).head.is_null() {
                        (*(*state).head).xflags = (hold & 0xff) as c_int;
                        (*(*state).head).os = (hold >> 8) as c_int;
                    }
                    if ((*state).flags & 0x0200) != 0 && ((*state).wrap & 4) != 0 {
                        (*state).check = crc2((*state).check, hold);
                    }
                    initbits!();
                    (*state).mode = EXLEN;
                }

                EXLEN => {
                    if (*state).flags & 0x0400 != 0 {
                        needbits!(16);
                        (*state).length = u32::from(hold as u16);
                        if !(*state).head.is_null() {
                            (*(*state).head).extra_len = u32::from(hold as u16);
                        }
                        if ((*state).flags & 0x0200) != 0 && ((*state).wrap & 4) != 0 {
                            (*state).check = crc2((*state).check, hold);
                        }
                        initbits!();
                    } else if !(*state).head.is_null() {
                        (*(*state).head).extra = ptr::null_mut();
                    }
                    (*state).mode = EXTRA;
                }

                EXTRA => {
                    if (*state).flags & 0x0400 != 0 {
                        copy = (*state).length;
                        if copy > have {
                            copy = have;
                        }
                        if copy != 0 {
                            let head = (*state).head;
                            if !head.is_null() && !(*head).extra.is_null() {
                                len = (*head).extra_len.wrapping_sub((*state).length);
                                if len < (*head).extra_max {
                                    let room = if len.wrapping_add(copy) > (*head).extra_max {
                                        (*head).extra_max - len
                                    } else {
                                        copy
                                    };
                                    ptr::copy_nonoverlapping(
                                        next,
                                        (*head).extra.add(len as usize),
                                        room as usize,
                                    );
                                }
                            }
                            if ((*state).flags & 0x0200) != 0 && ((*state).wrap & 4) != 0 {
                                (*state).check = c_ulong::from(crc32_small(
                                    (*state).check as u32,
                                    next,
                                    copy as usize,
                                ));
                            }
                            have -= copy;
                            next = next.add(copy as usize);
                            (*state).length -= copy;
                        }
                        if (*state).length != 0 {
                            break 'machine;
                        }
                    }
                    (*state).length = 0;
                    (*state).mode = NAME;
                }

                NAME => {
                    if (*state).flags & 0x0800 != 0 {
                        if have == 0 {
                            break 'machine;
                        }
                        let head = (*state).head;
                        copy = 0;
                        loop {
                            len = u32::from(*next.add(copy as usize));
                            copy += 1;
                            if !head.is_null()
                                && !(*head).name.is_null()
                                && (*state).length < (*head).name_max
                            {
                                *(*head).name.add((*state).length as usize) = len as u8;
                                (*state).length += 1;
                            }
                            if !(len != 0 && copy < have) {
                                break;
                            }
                        }
                        if ((*state).flags & 0x0200) != 0 && ((*state).wrap & 4) != 0 {
                            (*state).check = c_ulong::from(crc32_small(
                                (*state).check as u32,
                                next,
                                copy as usize,
                            ));
                        }
                        have -= copy;
                        next = next.add(copy as usize);
                        if len != 0 {
                            break 'machine;
                        }
                    } else if !(*state).head.is_null() {
                        (*(*state).head).name = ptr::null_mut();
                    }
                    (*state).length = 0;
                    (*state).mode = COMMENT;
                }

                COMMENT => {
                    if (*state).flags & 0x1000 != 0 {
                        if have == 0 {
                            break 'machine;
                        }
                        let head = (*state).head;
                        copy = 0;
                        loop {
                            len = u32::from(*next.add(copy as usize));
                            copy += 1;
                            if !head.is_null()
                                && !(*head).comment.is_null()
                                && (*state).length < (*head).comm_max
                            {
                                *(*head).comment.add((*state).length as usize) = len as u8;
                                (*state).length += 1;
                            }
                            if !(len != 0 && copy < have) {
                                break;
                            }
                        }
                        if ((*state).flags & 0x0200) != 0 && ((*state).wrap & 4) != 0 {
                            (*state).check = c_ulong::from(crc32_small(
                                (*state).check as u32,
                                next,
                                copy as usize,
                            ));
                        }
                        have -= copy;
                        next = next.add(copy as usize);
                        if len != 0 {
                            break 'machine;
                        }
                    } else if !(*state).head.is_null() {
                        (*(*state).head).comment = ptr::null_mut();
                    }
                    (*state).mode = HCRC;
                }

                HCRC => {
                    if (*state).flags & 0x0200 != 0 {
                        needbits!(16);
                        if ((*state).wrap & 4) != 0
                            && hold != u64::from((*state).check as u32 & 0xffff)
                        {
                            bad!(c"header crc mismatch");
                            continue;
                        }
                        initbits!();
                    }
                    if !(*state).head.is_null() {
                        (*(*state).head).hcrc = ((*state).flags >> 9) & 1;
                        (*(*state).head).done = 1;
                    }
                    /* compute crc32 checksum if not in raw mode */
                    if ((*state).wrap & 4) != 0 && (*state).flags != 0 {
                        (*state).check = c_ulong::from(CRC32_INITIAL_VALUE);
                        (*strm).adler = z_checksum_t::from(CRC32_INITIAL_VALUE);
                    }
                    (*state).mode = TYPE;
                }

                DICTID => {
                    needbits!(32);
                    let check = (hold as u32).swap_bytes();
                    (*state).check = c_ulong::from(check);
                    (*strm).adler = z_checksum_t::from(check);
                    initbits!();
                    (*state).mode = DICT;
                }

                DICT => {
                    if (*state).havedict == 0 {
                        restore!();
                        return Z_NEED_DICT;
                    }
                    (*state).check = c_ulong::from(ADLER32_INITIAL_VALUE);
                    (*strm).adler = z_checksum_t::from(ADLER32_INITIAL_VALUE);
                    (*state).mode = TYPE;
                }

                // C falls from TYPE into TYPEDO without storing the mode, so both are one case.
                TYPE | TYPEDO => {
                    if mode == TYPE && (flush == Z_BLOCK || flush == Z_TREES) {
                        break 'machine;
                    }

                    /* determine and dispatch block type */
                    /* hook for IBM Z DFLTCC */
                    #[cfg(feature = "s390-dfltcc-inflate")]
                    if dfltcc_inflate::dfltcc_can_inflate(strm) != 0 {
                        restore!();
                        let action = dfltcc_inflate::dfltcc_inflate(strm, flush, &mut ret);
                        load!();
                        if action == dfltcc_inflate::DFLTCC_INFLATE_CONTINUE {
                            continue;
                        } else if action == dfltcc_inflate::DFLTCC_INFLATE_BREAK {
                            break 'machine;
                        }
                    }
                    if (*state).last != 0 {
                        bytebits!();
                        (*state).mode = CHECK;
                        continue;
                    }
                    needbits!(3);
                    (*state).last = bits!(1) as c_int;
                    dropbits!(1);
                    match bits!(2) {
                        0 => {
                            /* stored block */
                            (*state).mode = STORED;
                        }
                        1 => {
                            /* fixed block */
                            fixedtables(state);
                            /* decode codes */
                            (*state).mode = LEN_;
                            if flush == Z_TREES {
                                dropbits!(2);
                                break 'machine;
                            }
                        }
                        2 => {
                            /* dynamic block */
                            (*state).mode = TABLE;
                        }
                        _ => {
                            bad!(c"invalid block type");
                        }
                    }
                    dropbits!(2);
                }

                STORED => {
                    /* get and verify stored block length */
                    /* go to byte boundary */
                    bytebits!();
                    needbits!(32);
                    if (hold & 0xffff) != ((hold >> 16) ^ 0xffff) {
                        bad!(c"invalid stored block lengths");
                        continue;
                    }
                    (*state).length = u32::from(hold as u16);
                    initbits!();
                    (*state).mode = COPY_;
                    if flush == Z_TREES {
                        break 'machine;
                    }
                }

                COPY_ => {
                    (*state).mode = COPY;
                }

                COPY => {
                    /* copy stored block from input to output */
                    copy = (*state).length;
                    if copy != 0 {
                        copy = copy.min(have);
                        copy = copy.min(left);
                        if copy == 0 {
                            break 'machine;
                        }
                        ptr::copy_nonoverlapping(next, put, copy as usize);
                        have -= copy;
                        next = next.add(copy as usize);
                        left -= copy;
                        put = put.add(copy as usize);
                        (*state).length -= copy;
                        continue;
                    }
                    (*state).mode = TYPE;
                }

                TABLE => {
                    /* get dynamic table entries descriptor */
                    needbits!(14);
                    (*state).nlen = bits!(5) + 257;
                    dropbits!(5);
                    (*state).ndist = bits!(5) + 1;
                    dropbits!(5);
                    (*state).ncode = bits!(4) + 4;
                    dropbits!(4);
                    if PKZIP_BUG_WORKAROUND == 0 && ((*state).nlen > 286 || (*state).ndist > 30) {
                        bad!(c"too many length or distance symbols");
                        continue;
                    }
                    (*state).have = 0;
                    (*state).mode = LENLENS;
                }

                LENLENS => {
                    let lens = (&raw mut (*state).lens).cast::<u16>();
                    /* get code length code lengths (not a typo) */
                    while (*state).have < (*state).ncode {
                        needbits!(3);
                        *lens.add(usize::from(*ORDER.get_unchecked((*state).have as usize))) =
                            bits!(3) as u16;
                        (*state).have += 1;
                        dropbits!(3);
                    }
                    while (*state).have < 19 {
                        *lens.add(usize::from(*ORDER.get_unchecked((*state).have as usize))) = 0;
                        (*state).have += 1;
                    }
                    (*state).next = (&raw mut (*state).codes).cast::<code>();
                    (*state).lencode = (*state).next;
                    (*state).distcode = (*state).next;
                    (*state).lenbits = 7;
                    ret = zng_inflate_table(
                        CODES,
                        lens,
                        19,
                        &raw mut (*state).next,
                        &raw mut (*state).lenbits,
                        (&raw mut (*state).work).cast::<u16>(),
                    );
                    if ret != 0 {
                        bad!(c"invalid code lengths set");
                        continue;
                    }
                    (*state).have = 0;
                    (*state).mode = CODELENS;
                }

                CODELENS => {
                    let lens = (&raw mut (*state).lens).cast::<u16>();
                    /* get length and distance code code lengths */
                    'lens: while (*state).have < (*state).nlen + (*state).ndist {
                        loop {
                            here = *(*state).lencode.add(bits!((*state).lenbits) as usize);
                            if u32::from(here.bits) <= u32::from(bits) {
                                break;
                            }
                            pullbyte!();
                        }
                        if here.val < 16 {
                            dropbits!(here.bits);
                            *lens.add((*state).have as usize) = here.val;
                            (*state).have += 1;
                        } else {
                            if here.val == 16 {
                                needbits!(u32::from(here.bits) + 2);
                                dropbits!(here.bits);
                                if (*state).have == 0 {
                                    bad!(c"invalid bit length repeat");
                                    break 'lens;
                                }
                                len = u32::from(*lens.add((*state).have as usize - 1));
                                copy = 3 + bits!(2);
                                dropbits!(2);
                            } else if here.val == 17 {
                                needbits!(u32::from(here.bits) + 3);
                                dropbits!(here.bits);
                                len = 0;
                                copy = 3 + bits!(3);
                                dropbits!(3);
                            } else {
                                needbits!(u32::from(here.bits) + 7);
                                dropbits!(here.bits);
                                len = 0;
                                copy = 11 + bits!(7);
                                dropbits!(7);
                            }
                            if (*state).have + copy > (*state).nlen + (*state).ndist {
                                bad!(c"invalid bit length repeat");
                                break 'lens;
                            }
                            while copy != 0 {
                                copy -= 1;
                                *lens.add((*state).have as usize) = len as u16;
                                (*state).have += 1;
                            }
                        }
                    }

                    /* handle error breaks in while */
                    if (*state).mode == BAD {
                        continue;
                    }

                    /* check for end-of-block code (better have one) */
                    if *lens.add(256) == 0 {
                        bad!(c"invalid code -- missing end-of-block");
                        continue;
                    }

                    /* build code tables -- note: do not change the lenbits or distbits
                    values here (MAX_LEN_ROOT_BITS and 9) without reading the comments
                    in inftrees.h concerning the ENOUGH constants, which depend on
                    those values, and the refill comments in inffast_tpl.h, which
                    depend on lenbits never exceeding MAX_LEN_ROOT_BITS */
                    (*state).next = (&raw mut (*state).codes).cast::<code>();
                    (*state).lencode = (*state).next;
                    (*state).lenbits = MAX_LEN_ROOT_BITS;
                    ret = zng_inflate_table(
                        LENS,
                        lens,
                        (*state).nlen,
                        &raw mut (*state).next,
                        &raw mut (*state).lenbits,
                        (&raw mut (*state).work).cast::<u16>(),
                    );
                    if ret != 0 {
                        bad!(c"invalid literal/lengths set");
                        continue;
                    }
                    (*state).distcode = (*state).next;
                    (*state).distbits = 9;
                    ret = zng_inflate_table(
                        DISTS,
                        lens.add((*state).nlen as usize),
                        (*state).ndist,
                        &raw mut (*state).next,
                        &raw mut (*state).distbits,
                        (&raw mut (*state).work).cast::<u16>(),
                    );
                    if ret != 0 {
                        bad!(c"invalid distances set");
                        continue;
                    }
                    (*state).mode = LEN_;
                    if flush == Z_TREES {
                        break 'machine;
                    }
                }

                LEN_ => {
                    (*state).mode = LEN;
                }

                // The states of one match. Each block ends where the next state starts, and the
                // inner match jumps to the state that the mode names.
                LEN | LENEXT | DIST | DISTEXT | MATCH => {
                    'copy: {
                        'distext: {
                            'dist: {
                                'lenext: {
                                    match mode {
                                        LEN => {}
                                        LENEXT => break 'lenext,
                                        DIST => break 'dist,
                                        DISTEXT => break 'distext,
                                        _ => break 'copy,
                                    }

                                    /* use inflate_fast() if we have enough input and output */
                                    if have >= INFLATE_FAST_MIN_HAVE as u32
                                        && left >= INFLATE_FAST_MIN_SAFE as u32
                                    {
                                        restore!();
                                        if likely(left >= INFLATE_FAST_MIN_LEFT as u32) {
                                            functable::inflate_fast(strm, out);
                                        } else {
                                            functable::inflate_fast_safe(strm, out);
                                        }
                                        load!();
                                        if (*state).mode == TYPE {
                                            (*state).back = -1;
                                        }
                                        continue 'machine;
                                    }
                                    (*state).back = 0;

                                    /* get a literal, length, or end-of-block code */
                                    loop {
                                        here =
                                            *(*state).lencode.add(bits!((*state).lenbits) as usize);
                                        if code_bits(here) <= u32::from(bits) {
                                            break;
                                        }
                                        pullbyte!();
                                    }
                                    if here.op != 0 && (here.op & 0xf0) == 0 {
                                        last = here;
                                        let last_bits = code_bits(last);
                                        loop {
                                            here = *(*state).lencode.add(
                                                usize::from(last.val)
                                                    + (bits!(last_bits + u32::from(last.op & 15))
                                                        >> last_bits)
                                                        as usize,
                                            );
                                            if last_bits + code_bits(here) <= u32::from(bits) {
                                                break;
                                            }
                                            pullbyte!();
                                        }
                                        dropbits!(last_bits);
                                        (*state).back += last_bits as c_int;
                                    }
                                    let here_bits = code_bits(here);
                                    dropbits!(here_bits);
                                    (*state).back += here_bits as c_int;
                                    (*state).length = u32::from(here.val);

                                    /* process literal */
                                    if here.op == 0 {
                                        (*state).mode = LIT;
                                        continue 'machine;
                                    }

                                    /* process end of block */
                                    if here.op & 32 != 0 {
                                        (*state).back = -1;
                                        (*state).mode = TYPE;
                                        continue 'machine;
                                    }

                                    /* invalid code */
                                    if here.op & 64 != 0 {
                                        bad!(c"invalid literal/length code");
                                        continue 'machine;
                                    }

                                    /* length code */
                                    (*state).extra = code_extra(here);
                                    (*state).mode = LENEXT;
                                }

                                /* get extra bits, if any */
                                if (*state).extra != 0 {
                                    needbits!((*state).extra);
                                    (*state).length += bits!((*state).extra);
                                    dropbits!((*state).extra);
                                    (*state).back += (*state).extra as c_int;
                                }
                                (*state).was = (*state).length;
                                (*state).mode = DIST;
                            }

                            /* get distance code */
                            loop {
                                here = *(*state).distcode.add(bits!((*state).distbits) as usize);
                                if code_bits(here) <= u32::from(bits) {
                                    break;
                                }
                                pullbyte!();
                            }
                            if (here.op & 0xf0) == 0 {
                                last = here;
                                let last_bits = code_bits(last);
                                loop {
                                    here = *(*state).distcode.add(
                                        usize::from(last.val)
                                            + (bits!(last_bits + u32::from(last.op & 15))
                                                >> last_bits)
                                                as usize,
                                    );
                                    if last_bits + code_bits(here) <= u32::from(bits) {
                                        break;
                                    }
                                    pullbyte!();
                                }
                                dropbits!(last_bits);
                                (*state).back += last_bits as c_int;
                            }
                            let here_bits = code_bits(here);
                            dropbits!(here_bits);
                            (*state).back += here_bits as c_int;
                            if here.op & 64 != 0 {
                                bad!(c"invalid distance code");
                                continue 'machine;
                            }
                            (*state).offset = u32::from(here.val);
                            (*state).extra = code_extra(here);
                            (*state).mode = DISTEXT;
                        }

                        /* get distance extra bits, if any */
                        if (*state).extra != 0 {
                            needbits!((*state).extra);
                            (*state).offset += bits!((*state).extra);
                            dropbits!((*state).extra);
                            (*state).back += (*state).extra as c_int;
                        }
                        #[cfg(feature = "inflate-strict")]
                        if (*state).offset > (*state).dmax {
                            bad!(c"invalid distance too far back");
                            continue 'machine;
                        }
                        (*state).mode = MATCH;
                    }

                    /* copy match from window to output */
                    if left == 0 {
                        break 'machine;
                    }
                    copy = out.wrapping_sub(left);
                    if (*state).offset > copy {
                        /* copy from window */
                        copy = (*state).offset - copy;
                        if copy > (*state).whave {
                            #[cfg(feature = "inflate-allow-invalid-dist")]
                            {
                                if (*state).sane != 0 {
                                    bad!(c"invalid distance too far back");
                                    continue;
                                }
                                copy -= (*state).whave;
                                copy = copy.min((*state).length);
                                copy = copy.min(left);
                                left -= copy;
                                (*state).length -= copy;
                                loop {
                                    *put = 0;
                                    put = put.add(1);
                                    copy = copy.wrapping_sub(1);
                                    if copy == 0 {
                                        break;
                                    }
                                }
                                if (*state).length == 0 {
                                    (*state).mode = LEN;
                                }
                            }
                            #[cfg(not(feature = "inflate-allow-invalid-dist"))]
                            bad!(c"invalid distance too far back");
                            continue;
                        }
                        /* where to copy match bytes from */
                        let from = if copy > (*state).wnext {
                            copy -= (*state).wnext;
                            (*state).window.add(((*state).wsize - copy) as usize)
                        } else {
                            (*state).window.add(((*state).wnext - copy) as usize)
                        };
                        copy = copy.min((*state).length);
                        copy = copy.min(left);

                        put = chunkcopy_safe(put, from, copy as usize, put.add(left as usize));
                    } else {
                        copy = (*state).length.min(left);

                        put = functable::chunkmemset_safe(
                            put,
                            put.sub((*state).offset as usize),
                            copy as usize,
                            left as usize,
                        );
                    }
                    left -= copy;
                    (*state).length -= copy;
                    if (*state).length == 0 {
                        (*state).mode = LEN;
                    }
                }

                LIT => {
                    if left == 0 {
                        break 'machine;
                    }
                    *put = (*state).length as u8;
                    put = put.add(1);
                    left -= 1;
                    (*state).mode = LEN;
                }

                CHECK => {
                    if (*state).wrap != 0 {
                        needbits!(32);
                        out = out.wrapping_sub(left);
                        (*strm).total_out = (*strm).total_out.wrapping_add(out as z_uintmax_t);
                        (*state).total = (*state).total.wrapping_add(c_ulong::from(out));

                        /* compute crc32 checksum if not in raw mode */
                        if inflate_need_checksum(strm) && ((*state).wrap & 4) != 0 && out != 0 {
                            inf_chksum(strm, put.sub(out as usize), out);
                        }
                        out = left;
                        let value = if (*state).flags != 0 {
                            hold
                        } else {
                            u64::from((hold as u32).swap_bytes())
                        };
                        if ((*state).wrap & 4) != 0 && value != (*state).check as u64 {
                            bad!(c"incorrect data check");
                            continue;
                        }
                        initbits!();
                    }
                    (*state).mode = LENGTH;
                }

                LENGTH => {
                    if (*state).wrap != 0 && (*state).flags != 0 {
                        needbits!(32);
                        if ((*state).wrap & 4) != 0 && hold != ((*state).total as u64 & 0xffffffff)
                        {
                            bad!(c"incorrect length check");
                            continue;
                        }
                        initbits!();
                    }
                    (*state).mode = DONE;
                }

                DONE => {
                    /* inflate stream terminated properly */
                    ret = Z_STREAM_END;
                    break 'machine;
                }

                BAD => {
                    ret = Z_DATA_ERROR;
                    break 'machine;
                }

                /* SYNC, and can't happen, but makes compilers happy */
                _ => return Z_STREAM_ERROR,
            }
        }

        /*
          Return from inflate(), updating the total counts and the check value.
          If there was no progress during the inflate() call, return a buffer
          error.  Call updatewindow() to create and/or update the window state.
        */
        restore!();
        // The stream now holds put, left and have. C reads them back from it, which costs
        // nothing there. Here the compiler cannot tell that the stores to the state leave the
        // stream alone, so it would load each one again behind the stores.
        let check_bytes = out.wrapping_sub(left);
        if inflate_need_updatewindow(strm)
            && ((*state).wsize != 0
                || (out != left
                    && (*state).mode < BAD
                    && ((*state).mode < CHECK || flush != Z_FINISH)))
        {
            /* update sliding window with respective checksum if not in "raw" mode */
            updatewindow(strm, put, check_bytes, (*state).wrap & 4);
        }
        input = input.wrapping_sub(have);
        out = out.wrapping_sub(left);
        (*strm).total_in = (*strm).total_in.wrapping_add(input as z_uintmax_t);
        (*strm).total_out = (*strm).total_out.wrapping_add(out as z_uintmax_t);
        (*state).total = (*state).total.wrapping_add(c_ulong::from(out));

        (*strm).data_type = (*state).bits as c_int
            + if (*state).last != 0 { 64 } else { 0 }
            + if (*state).mode == TYPE { 128 } else { 0 }
            + if (*state).mode == LEN_ || (*state).mode == COPY_ {
                256
            } else {
                0
            };
        if ((input == 0 && out == 0) || flush == Z_FINISH) && ret == Z_OK {
            /* when no sliding window is used, hash the output bytes if no CHECK state */
            if inflate_need_checksum(strm) && (*state).wsize == 0 && flush == Z_FINISH {
                inf_chksum(strm, put.wrapping_sub(check_bytes as usize), check_bytes);
            }
            ret = Z_BUF_ERROR;
        }
        ret
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflateEnd"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateEnd(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }

        /* Free allocated buffers */
        free_inflate(strm);

        Z_OK
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up. `dictionary` must be null or valid
/// for writes of the window size, and `dictLength` null or valid for writes.
#[unsafe(export_name = prefix!("inflateGetDictionary"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateGetDictionary(
    strm: *mut z_stream,
    dictionary: *mut u8,
    dictLength: *mut u32,
) -> i32 {
    // SAFETY: the caller guarantees the stream and both pointers, and inflateStateCheck vouches
    // for the state. The window holds whave bytes, of which wnext are at its start.
    unsafe {
        /* check state */
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();

        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-inflate")]
        if dfltcc_inflate::dfltcc_can_inflate(strm) != 0 {
            return dfltcc_inflate::dfltcc_inflate_get_dictionary(strm, dictionary, dictLength);
        }

        /* copy dictionary */
        if (*state).whave != 0 && !dictionary.is_null() {
            let whave = (*state).whave as usize;
            let wnext = (*state).wnext as usize;
            ptr::copy_nonoverlapping((*state).window.add(wnext), dictionary, whave - wnext);
            ptr::copy_nonoverlapping((*state).window, dictionary.add(whave - wnext), wnext);
        }
        if !dictLength.is_null() {
            *dictLength = (*state).whave;
        }
        Z_OK
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up, and `dictionary` must be valid for
/// reads of `dictLength` bytes.
#[unsafe(export_name = prefix!("inflateSetDictionary"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateSetDictionary(
    strm: *mut z_stream,
    dictionary: *const u8,
    dictLength: u32,
) -> i32 {
    // SAFETY: the caller guarantees the stream and the dictionary, and inflateStateCheck vouches
    // for the state.
    unsafe {
        /* check state */
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        if (*state).wrap != 0 && (*state).mode != DICT {
            return Z_STREAM_ERROR;
        }

        /* check for correct dictionary identifier */
        if (*state).mode == DICT {
            let dictid = functable::adler32(ADLER32_INITIAL_VALUE, dictionary, dictLength as usize);
            if c_ulong::from(dictid) != (*state).check {
                return Z_DATA_ERROR;
            }
        }

        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-inflate")]
        if dfltcc_inflate::dfltcc_can_inflate(strm) != 0 {
            return dfltcc_inflate::dfltcc_inflate_set_dictionary(strm, dictionary, dictLength);
        }

        /* copy dictionary to window using updatewindow(), which will amend the
        existing dictionary if appropriate */
        updatewindow(
            strm,
            dictionary.wrapping_add(dictLength as usize),
            dictLength,
            0,
        );

        (*state).havedict = 1;
        Z_OK
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up, and `head` must be valid for writes
/// until the stream ends or is reset.
#[unsafe(export_name = prefix!("inflateGetHeader"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateGetHeader(strm: *mut z_stream, head: *mut gz_header) -> i32 {
    // SAFETY: the caller guarantees the stream and the header, and inflateStateCheck vouches
    // for the state.
    unsafe {
        /* check state */
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        if ((*state).wrap & 2) == 0 {
            return Z_STREAM_ERROR;
        }

        /* save header structure */
        (*state).head = head;
        (*head).done = 0;
        Z_OK
    }
}

/*
  Search buf[0..len-1] for the pattern: 0, 0, 0xff, 0xff.  Return when found
  or when out of input.  When called, *have is the number of pattern bytes
  found in order so far, in 0..3.  On return *have is updated to the new
  state.  If on return *have equals four, then the pattern was found and the
  return value is how many bytes were read including the last byte of the
  pattern.  If *have is less than four, then the pattern has not been found
  yet and the return value is len.  In the latter case, syncsearch() can be
  called again with more data and the *have state.  *have is initialized to
  zero for the first call.
*/
/// # Safety
///
/// `have` must be valid for reads and writes, and `buf` for reads of `len` bytes.
unsafe fn syncsearch(have: *mut u32, buf: *const u8, len: u32) -> u32 {
    // SAFETY: the caller guarantees both pointers.
    unsafe {
        let mut got = *have;
        let mut next = 0;
        while next < len && got < 4 {
            let byte = *buf.add(next as usize);
            if byte == (if got < 2 { 0 } else { 0xff }) {
                got += 1;
            } else if byte != 0 {
                got = 0;
            } else {
                got = 4 - got;
            }
            next += 1;
        }
        *have = got;
        next
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up, with next_in valid for reads of
/// avail_in bytes.
#[unsafe(export_name = prefix!("inflateSync"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateSync(strm: *mut z_stream) -> i32 {
    /* number of bytes to look at or looked at */
    let mut len: u32;
    /* to restore bit buffer to byte string */
    let mut buf = [0u8; 4];

    // SAFETY: the caller guarantees the stream and its input, and inflateStateCheck vouches for
    // the state.
    unsafe {
        /* check parameters */
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        if (*strm).avail_in == 0 && (*state).bits < 8 {
            return Z_BUF_ERROR;
        }

        /* if first time, start search in bit buffer */
        if (*state).mode != SYNC {
            (*state).mode = SYNC;
            (*state).hold >>= (*state).bits & 7;
            (*state).bits -= (*state).bits & 7;
            len = 0;
            while (*state).bits >= 8 {
                // The bit buffer never holds more than four whole bytes ahead of a search.
                if let Some(byte) = buf.get_mut(len as usize) {
                    *byte = (*state).hold as u8;
                }
                len += 1;
                (*state).hold >>= 8;
                (*state).bits -= 8;
            }
            (*state).have = 0;
            syncsearch(&raw mut (*state).have, buf.as_ptr(), len.min(4));
        }

        /* search available input */
        len = syncsearch(&raw mut (*state).have, (*strm).next_in, (*strm).avail_in);
        (*strm).avail_in -= len;
        (*strm).next_in = (*strm).next_in.wrapping_add(len as usize);
        (*strm).total_in = (*strm).total_in.wrapping_add(len as z_uintmax_t);

        /* return no joy or set up to restart inflate() on a new block */
        if (*state).have != 4 {
            return Z_DATA_ERROR;
        }
        if (*state).flags == -1 {
            /* if no header yet, treat as raw */
            (*state).wrap = 0;
        } else {
            /* no point in computing a check value now */
            (*state).wrap &= !4;
        }
        /* temporary to save header status */
        let flags = (*state).flags;
        /* temporary to save total_in and total_out */
        let total_in = (*strm).total_in;
        let total_out = (*strm).total_out;
        inflateReset(strm);
        (*strm).total_in = total_in;
        (*strm).total_out = total_out;
        (*state).flags = flags;
        (*state).mode = TYPE;
        Z_OK
    }
}

/*
  Returns true if inflate is currently at the end of a block generated by
  Z_SYNC_FLUSH or Z_FULL_FLUSH. This function is used by one PPP
  implementation to provide an additional safety check. PPP uses
  Z_SYNC_FLUSH but removes the length bytes of the resulting empty stored
  block. When decompressing, PPP checks that at the end of input packet,
  inflate is waiting for these length bytes.
*/
/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflateSyncPoint"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateSyncPoint(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        #[cfg(feature = "s390-dfltcc-inflate")]
        if dfltcc_inflate::dfltcc_was_inflate_used(strm) != 0 {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        i32::from((*state).mode == STORED && (*state).bits == 0)
    }
}

/// # Safety
///
/// `source` must be null or a stream that inflateInit set up, and `dest` null or valid for
/// writes.
#[unsafe(export_name = prefix!("inflateCopy"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateCopy(dest: *mut z_stream, source: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees both streams, and inflateStateCheck vouches for the state of
    // the source. The new allocation holds a whole state and window.
    unsafe {
        /* check input */
        if inflateStateCheck(source) || dest.is_null() {
            return Z_STREAM_ERROR;
        }
        let state = (*source).state.cast::<inflate_state>();

        /* copy stream */
        ptr::copy(source.cast_const(), dest, 1);

        /* allocate space */
        let alloc_bufs = alloc_inflate(dest);
        if alloc_bufs.is_null() {
            return Z_MEM_ERROR;
        }
        let copy = (*alloc_bufs).state;

        /* copy state */
        ptr::copy_nonoverlapping(state.cast::<u8>(), copy.cast::<u8>(), INFLATE_STATE_SIZE);
        (*copy).strm = dest;
        let codes = (&raw const (*state).codes).cast::<code>();
        let copy_codes = (&raw mut (*copy).codes).cast::<code>();
        if (*state).lencode >= codes && (*state).lencode <= codes.add(ENOUGH - 1) {
            (*copy).lencode = copy_codes.add((*state).lencode.offset_from_unsigned(codes));
            (*copy).distcode = copy_codes
                .cast::<u8>()
                .wrapping_add((*state).distcode.addr().wrapping_sub(codes.addr()))
                .cast::<code>();
        }
        (*copy).next = copy_codes
            .cast::<u8>()
            .wrapping_add((*state).next.addr().wrapping_sub(codes.addr()))
            .cast::<code>();
        (*copy).window = (*alloc_bufs).window;
        (*copy).alloc_bufs = alloc_bufs;

        /* window */
        ptr::copy_nonoverlapping(
            (*state).window,
            (*copy).window,
            inflate_adjust_window_size((*state).wsize as usize),
        );

        (*dest).state = copy.cast::<internal_state>();
        Z_OK
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflateUndermine"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateUndermine(strm: *mut z_stream, subvert: i32) -> i32 {
    #[cfg(feature = "inflate-allow-invalid-dist")]
    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        (*state).sane = i32::from(subvert == 0);
        Z_OK
    }
    #[cfg(not(feature = "inflate-allow-invalid-dist"))]
    {
        let _ = (strm, subvert);
        Z_DATA_ERROR
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflateValidate"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateValidate(strm: *mut z_stream, check: i32) -> i32 {
    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        if inflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();
        if check != 0 && (*state).wrap != 0 {
            (*state).wrap |= 4;
        } else {
            (*state).wrap &= !4;
        }
        Z_OK
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateInit set up.
#[unsafe(export_name = prefix!("inflateMark"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateMark(strm: *mut z_stream) -> c_long {
    // SAFETY: the caller guarantees the stream, and inflateStateCheck vouches for the state.
    unsafe {
        if inflateStateCheck(strm) {
            return -65536;
        }
        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-inflate")]
        if dfltcc_inflate::dfltcc_was_inflate_used(strm) != 0 {
            return -(1 << 16);
        }
        let state = (*strm).state.cast::<inflate_state>();
        let progress = if (*state).mode == COPY {
            (*state).length
        } else if (*state).mode == MATCH {
            (*state).was.wrapping_sub((*state).length)
        } else {
            0
        };
        ((((*state).back as c_long as c_ulong) << 16) as c_long).wrapping_add(progress as c_long)
    }
}

/// # Safety
///
/// `strm` must be null or valid for reads, with a state that is null or an inflate state.
#[unsafe(export_name = prefix!("inflateCodesUsed"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateCodesUsed(strm: *mut z_stream) -> c_ulong {
    // SAFETY: the caller guarantees the stream and its state.
    unsafe {
        if strm.is_null() || (*strm).state.is_null() {
            return c_ulong::MAX;
        }
        let state = (*strm).state.cast::<inflate_state>();
        let codes = (&raw const (*state).codes).cast::<code>();
        let used = ((*state).next.addr() as isize).wrapping_sub(codes.addr() as isize);
        (used / size_of::<code>() as isize) as c_ulong
    }
}
