//! Port of the parts of dfltcc_deflate.h that the Rust sources need.

use core::ffi::c_int;

use crate::zbuild::prefix;
use crate::zlib::z_stream;

unsafe extern "C" {
    #[link_name = prefix!("dfltcc_can_deflate")]
    fn dfltcc_can_deflate(strm: *mut z_stream) -> c_int;
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
