//! zlib data compression library for the next generation systems.
//!
//! Each module replaces the C source file of the same name and exports the same symbols.

#![no_std]

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
