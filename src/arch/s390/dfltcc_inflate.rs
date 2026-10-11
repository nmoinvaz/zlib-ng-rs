//! Port of the parts of dfltcc_inflate.h that the Rust sources need.

use core::ffi::{c_int, c_uint};

use crate::zbuild::prefix;
use crate::zlib::z_stream;

/// What inflate does after the hardware had its turn, dfltcc_inflate_action in C
#[allow(non_camel_case_types)]
pub(crate) type dfltcc_inflate_action = c_uint;
pub(crate) const DFLTCC_INFLATE_CONTINUE: dfltcc_inflate_action = 0;
pub(crate) const DFLTCC_INFLATE_BREAK: dfltcc_inflate_action = 1;

unsafe extern "C" {
    #[link_name = prefix!("dfltcc_reset_inflate_state")]
    pub(crate) fn dfltcc_reset_inflate_state(strm: *mut z_stream);
    #[link_name = prefix!("dfltcc_can_inflate")]
    pub(crate) fn dfltcc_can_inflate(strm: *mut z_stream) -> c_int;
    #[link_name = prefix!("dfltcc_inflate")]
    pub(crate) fn dfltcc_inflate(
        strm: *mut z_stream,
        flush: c_int,
        ret: *mut c_int,
    ) -> dfltcc_inflate_action;
    #[link_name = prefix!("dfltcc_was_inflate_used")]
    pub(crate) fn dfltcc_was_inflate_used(strm: *mut z_stream) -> c_int;
    #[link_name = prefix!("dfltcc_inflate_disable")]
    pub(crate) fn dfltcc_inflate_disable(strm: *mut z_stream) -> c_int;
    #[link_name = prefix!("dfltcc_inflate_set_dictionary")]
    pub(crate) fn dfltcc_inflate_set_dictionary(
        strm: *mut z_stream,
        dictionary: *const u8,
        dict_length: c_uint,
    ) -> c_int;
    #[link_name = prefix!("dfltcc_inflate_get_dictionary")]
    pub(crate) fn dfltcc_inflate_get_dictionary(
        strm: *mut z_stream,
        dictionary: *mut u8,
        dict_length: *mut c_uint,
    ) -> c_int;
}
