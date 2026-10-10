//! Declarations for the parts of deflate.h and deflate.c that are still built from C.

#[cfg(feature = "zlib-compat")]
use core::ffi::c_char;
use core::ffi::{c_int, c_uint, c_void};

use crate::zbuild::prefix;
#[cfg(feature = "zlib-compat")]
use crate::zlib::ZLIB_VERSION;
use crate::zlib::z_stream;

unsafe extern "C" {
    #[cfg(not(feature = "zlib-compat"))]
    #[link_name = "zng_deflateInit"]
    pub(crate) fn deflateInit(strm: *mut z_stream, level: i32) -> i32;
    #[cfg(feature = "zlib-compat")]
    fn deflateInit_(
        strm: *mut z_stream,
        level: i32,
        version: *const c_char,
        stream_size: i32,
    ) -> i32;
    #[link_name = prefix!("deflate")]
    pub(crate) fn deflate(strm: *mut z_stream, flush: i32) -> i32;
    #[link_name = prefix!("deflateEnd")]
    pub(crate) fn deflateEnd(strm: *mut z_stream) -> i32;
}

/// deflateInit is a macro in zlib.h to allow checking the zlib version
/// and the compiler's view of z_stream
///
/// # Safety
///
/// `strm` must be valid for reads and writes.
#[cfg(feature = "zlib-compat")]
#[allow(non_snake_case)]
#[inline]
pub(crate) unsafe fn deflateInit(strm: *mut z_stream, level: i32) -> i32 {
    // SAFETY: the caller guarantees strm is valid and the version is a NUL terminated string.
    unsafe {
        deflateInit_(
            strm,
            level,
            ZLIB_VERSION.as_ptr(),
            size_of::<z_stream>() as i32,
        )
    }
}

/// number of elements in hash table
pub(crate) const HASH_SIZE: usize = 65536;
/// log2(HASH_SIZE)
pub(crate) const HASH_BITS: u32 = 16;

/// A Pos is an index in the character window.
#[allow(non_camel_case_types)]
pub(crate) type Pos = u16;

/// The leading fields of the C deflate_state, up to the last one that the Rust sources use. The
/// structure is longer than this in C, so it must only be used through a pointer. The build
/// checks every field offset against the C definition.
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
pub struct deflate_state {
    /* Cacheline 0 */
    /// pointer back to this zlib stream
    pub(crate) strm: *mut z_stream,
    /// output still pending
    pub(crate) pending_buf: *mut u8,
    /// next pending byte to output to the stream
    pub(crate) pending_out: *mut u8,
    /// size of pending_buf
    pub(crate) pending_buf_size: u32,
    /// nb of bytes in the pending buffer
    pub(crate) pending: u32,
    /// bit 0 true for zlib, bit 1 true for gzip
    pub(crate) wrap: c_int,
    /// where in extra, name, or comment
    pub(crate) gzindex: u32,
    /// gzip header information to write
    pub(crate) gzhead: *mut c_void,
    /// as the name implies
    pub(crate) status: c_int,
    /// value of flush param for previous deflate call
    pub(crate) last_flush: c_int,
    /// Whether reproducible compression results are required.
    pub(crate) reproducible: c_int,

    /// Whether or not a block is currently open for the QUICK deflation scheme.
    /// This is set to 1 if there is an active block, or 0 if the block was just closed.
    pub(crate) block_open: c_uint,

    /* Cacheline 1 */
    /// number of valid bytes ahead in window
    pub(crate) lookahead: c_uint,
    /// start of string to insert
    pub(crate) strstart: c_uint,
    /// LZ77 window size (32K by default)
    pub(crate) w_size: c_uint,

    /// Window position at the beginning of the current output block.
    /// Gets negative when the window is moved backwards.
    pub(crate) block_start: c_int,

    /// High water mark offset in window for initialized bytes -- bytes above
    /// this are set to zero in order to avoid memory check warnings when
    /// longest match routines access bytes past the input.  This is then
    /// updated to the new high water mark.
    pub(crate) high_water: c_uint,

    /// Actual size of window: 2*wSize, except when the user input buffer
    /// is directly used as sliding window.
    pub(crate) window_size: c_uint,

    /// Sliding window. Input bytes are read into the second half of the window,
    /// and move to the first half later to keep a dictionary of at least wSize
    /// bytes. With this organization, matches are limited to a distance of
    /// wSize-STD_MAX_MATCH bytes, but this ensures that IO is always
    /// performed with a length multiple of the block size. Also, it limits
    /// the window size to 64K, which is quite useful on MSDOS.
    /// To do: use the user input buffer as sliding window.
    pub(crate) window: *mut u8,

    /// Link to older string with same hash index. To limit the size of this
    /// array to 64K, this link is maintained only for the last 32K strings.
    /// An index in this array is thus a window index modulo 32K.
    pub(crate) prev: *mut Pos,

    /// Heads of the hash chains or 0.
    pub(crate) head: *mut Pos,

    /// hash index of string to be inserted
    pub(crate) ins_h: u32,
}

/// Window mask: w_size is always a power of 2, so w_mask = w_size - 1
///
/// # Safety
///
/// `s` must point to a deflate_state.
#[inline(always)]
pub(crate) unsafe fn w_mask(s: *const deflate_state) -> c_uint {
    // SAFETY: the caller guarantees s is valid.
    unsafe { (*s).w_size - 1 }
}
