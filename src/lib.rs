//! zlib data compression library for the next generation systems.
//!
//! Each module replaces the C source file of the same name and exports the same symbols.

#![no_std]

pub mod adler32;
mod adler32_p;
mod arch;
pub mod compress;
pub mod crc32;
pub mod crc32_braid_comb;
mod crc32_braid_comb_p;
mod crc32_braid_p;
mod crc32_braid_tbl;
mod crc32_chorba_p;
mod crc32_p;
mod deflate;
mod functable;
mod inflate;
pub mod uncompr;
pub mod zbuild;
pub mod zconf;
pub mod zlib;
mod zutil;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn abort() -> !;
    }
    // SAFETY: abort has no preconditions.
    unsafe { abort() }
}

/// The prebuilt core library refers to this from its unwind tables, which are never used because
/// panics abort.
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}
