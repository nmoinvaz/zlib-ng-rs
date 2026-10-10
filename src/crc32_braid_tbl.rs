//! crc32_braid_tbl.h -- tables for braided CRC calculation
//!
//! The tables are computed at compile time, the way makecrct.c generates them.
//!
//! makecrct.c -- output crc32 tables
//! Copyright (C) 1995-2022 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use crate::crc32_braid_comb_p::{multmodp, x2nmodp};
use crate::crc32_braid_p::{BRAID_N, BRAID_W, POLY, z_word_t};

/*
  Generate tables for a byte-wise 32-bit CRC calculation on the polynomial:
  x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+x^8+x^7+x^5+x^4+x^2+x+1.

  Polynomials over GF(2) are represented in binary, one bit per coefficient,
  with the lowest powers in the most significant bit. Then adding polynomials
  is just exclusive-or, and multiplying a polynomial by x is a right shift by
  one. If we call the above polynomial p, and represent a byte as the
  polynomial q, also with the lowest power in the most significant bit (so the
  byte 0xb1 is the polynomial x^7+x^3+x^2+1), then the CRC is (q*x^32) mod p,
  where a mod b means the remainder after dividing a by b.

  This calculation is done using the shift-register method of multiplying and
  taking the remainder. The register is initialized to zero, and for each
  incoming bit, x^32 is added mod p to the register if the bit is a one (where
  x^32 mod p is p+x^32 = x^26+...+1), and the register is multiplied mod p by x
  (which is shifting right by one and adding x^32 mod p if the bit shifted out
  is a one). We start with the highest power (least significant bit) of q and
  repeat for all eight bits of q.

  The table is simply the CRC of all possible eight bit values. This is all the
  information needed to generate CRCs on data a byte at a time for all
  combinations of CRC register values and incoming bytes.
*/
pub(crate) static CRC_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut p = i as u32;
        let mut j = 0;
        while j < 8 {
            p = if p & 1 != 0 { (p >> 1) ^ POLY } else { p >> 1 };
            j += 1;
        }
        table[i] = p;
        i += 1;
    }
    table
};

/// The x^2^n mod p(x) table
pub(crate) const X2N_TABLE: [u32; 32] = {
    let mut table = [0; 32];
    let mut p = 1u32 << 30; /* x^1 */
    table[0] = p;
    let mut n = 1;
    while n < 32 {
        p = multmodp(p, p);
        table[n] = p;
        n += 1;
    }
    table
};

pub(crate) static CRC_BRAID_TABLE: [[u32; 256]; BRAID_W] = {
    let mut ltl = [[0; 256]; BRAID_W];
    let mut k = 0;
    while k < BRAID_W {
        let p = x2nmodp(((BRAID_N * BRAID_W + 3 - k) << 3) as i64, 0);
        let mut i = 1;
        while i < 256 {
            ltl[k][i] = multmodp((i as u32) << 24, p);
            i += 1;
        }
        k += 1;
    }
    ltl
};

#[cfg(target_endian = "big")]
pub(crate) static CRC_BIG_TABLE: [z_word_t; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = (CRC_TABLE[i] as z_word_t).swap_bytes();
        i += 1;
    }
    table
};

#[cfg(target_endian = "big")]
pub(crate) static CRC_BRAID_BIG_TABLE: [[z_word_t; 256]; BRAID_W] = {
    let mut big = [[0; 256]; BRAID_W];
    let mut k = 0;
    while k < BRAID_W {
        let mut i = 1;
        while i < 256 {
            big[BRAID_W - 1 - k][i] = (CRC_BRAID_TABLE[k][i] as z_word_t).swap_bytes();
            i += 1;
        }
        k += 1;
    }
    big
};

/// Looks up byte k of a word in the braid table for the target byte order
#[inline(always)]
pub(crate) fn braid_table(k: usize, byte: u8) -> z_word_t {
    #[cfg(target_endian = "little")]
    return CRC_BRAID_TABLE[k][usize::from(byte)] as z_word_t;
    #[cfg(target_endian = "big")]
    return CRC_BRAID_BIG_TABLE[k][usize::from(byte)];
}
