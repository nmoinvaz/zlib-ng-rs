//! Port of the parts of dfltcc_deflate.h that the Rust sources need.

use core::ffi::{c_int, c_uint};

use crate::deflate::block_state;

use crate::zbuild::prefix;
use crate::zlib::z_stream;

unsafe extern "C" {
    #[link_name = prefix!("dfltcc_reset_deflate_state")]
    pub(crate) fn dfltcc_reset_deflate_state(strm: *mut z_stream);
    #[link_name = prefix!("dfltcc_can_deflate")]
    pub(crate) fn dfltcc_can_deflate(strm: *mut z_stream) -> c_int;
    #[link_name = prefix!("dfltcc_deflate")]
    pub(crate) fn dfltcc_deflate(
        strm: *mut z_stream,
        flush: c_int,
        result: *mut block_state,
    ) -> c_int;
    #[link_name = prefix!("dfltcc_deflate_params")]
    pub(crate) fn dfltcc_deflate_params(
        strm: *mut z_stream,
        level: c_int,
        strategy: c_int,
        flush: *mut c_int,
    ) -> c_int;
    #[link_name = prefix!("dfltcc_deflate_done")]
    pub(crate) fn dfltcc_deflate_done(strm: *mut z_stream, flush: c_int) -> c_int;
    // Only zng_deflateSetParams asks, which the zlib compatible API does not have.
    #[cfg(not(feature = "zlib-compat"))]
    #[link_name = prefix!("dfltcc_can_set_reproducible")]
    pub(crate) fn dfltcc_can_set_reproducible(strm: *mut z_stream, reproducible: c_int) -> c_int;
    #[link_name = prefix!("dfltcc_deflate_set_dictionary")]
    pub(crate) fn dfltcc_deflate_set_dictionary(
        strm: *mut z_stream,
        dictionary: *const u8,
        dict_length: c_uint,
    ) -> c_int;
    #[link_name = prefix!("dfltcc_deflate_get_dictionary")]
    pub(crate) fn dfltcc_deflate_get_dictionary(
        strm: *mut z_stream,
        dictionary: *mut u8,
        dict_length: *mut c_uint,
    ) -> c_int;
}

/// DEFLATE_NEED_CHECKSUM in C
///
/// # Safety
///
/// `strm` must be a valid deflate stream.
#[inline(always)]
pub(crate) unsafe fn deflate_need_checksum(strm: *mut z_stream) -> bool {
    // SAFETY: the caller guarantees the stream is valid.
    unsafe { dfltcc_can_deflate(strm) == 0 }
}
