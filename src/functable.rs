//! Declarations for the functable entry points that are still built from C.

unsafe extern "C" {
    pub(crate) fn functable_adler32(adler: u32, buf: *const u8, len: usize) -> u32;
}
