//! Declarations for the parts of trees.h and trees.c that are still built from C.

use core::ffi::c_int;

use crate::deflate::deflate_state;

unsafe extern "C" {
    pub(crate) fn zng_tr_flush_block(
        s: *mut deflate_state,
        buf: *mut u8,
        stored_len: u32,
        last: c_int,
    );
}
