//! Port of crc32_braid_comb_p.h.

use crate::crc32_braid_p::POLY;
use crate::crc32_braid_tbl::X2N_TABLE;

/*
  Return a(x) multiplied by b(x) modulo p(x), where p(x) is the CRC polynomial,
  reflected. For speed, this requires that a not be zero.
*/
pub(crate) const fn multmodp(a: u32, mut b: u32) -> u32 {
    let mut m = 1u32 << 31;
    let mut p = 0;
    loop {
        if a & m != 0 {
            p ^= b;
            if a & (m - 1) == 0 {
                break;
            }
        }
        m >>= 1;
        b = if b & 1 != 0 { (b >> 1) ^ POLY } else { b >> 1 };
    }
    p
}

/*
  Return x^(n * 2^k) modulo p(x). Requires that x2n_table[] has been
  initialized.
*/
pub(crate) const fn x2nmodp(mut n: i64, mut k: u32) -> u32 {
    let mut p = 1u32 << 31; /* x^0 == 1 */
    while n != 0 {
        if n & 1 != 0 {
            p = multmodp(X2N_TABLE[(k & 31) as usize], p);
        }
        n >>= 1;
        k += 1;
    }
    p
}
