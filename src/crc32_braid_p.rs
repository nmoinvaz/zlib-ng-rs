//! Port of crc32_braid_p.h.

/* Define BRAID_N, valid range is 1..6 */
pub(crate) const BRAID_N: usize = 5;

/* Define BRAID_W and the associated z_word_t type. If BRAID_W is not defined, then a braided
   calculation is not used, and the associated tables and code are not compiled.

   TODO: According to crc32_braid_c.c, BRAID_N=5, BRAID_W=4 is fastest with Sparc64-VII,
   PowerPC POWER9, and MIPS64 Octeon II processors.
*/
#[cfg(target_pointer_width = "64")]
pub(crate) const BRAID_W: usize = 8;
#[cfg(target_pointer_width = "64")]
#[allow(non_camel_case_types)]
pub(crate) type z_word_t = u64;
#[cfg(not(target_pointer_width = "64"))]
pub(crate) const BRAID_W: usize = 4;
#[cfg(not(target_pointer_width = "64"))]
#[allow(non_camel_case_types)]
pub(crate) type z_word_t = u32;

/* CRC polynomial. */
/// p(x) reflected, with x^32 implied
pub(crate) const POLY: u32 = 0xedb88320;
