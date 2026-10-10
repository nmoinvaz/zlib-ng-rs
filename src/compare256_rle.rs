//! compare256_rle.h -- 256 byte run-length encoding comparison
//! Copyright (C) 2022 Nathan Moinvaziri
//! For conditions of distribution and use, see copyright notice in zlib.h

use crate::fallback_builtins::zng_first_diff_byte64;
use crate::zbuild::OPTIMAL_CMP;

/* 8-bit RLE comparison for hardware without unaligned loads */
#[inline(always)]
fn compare256_rle_8(src0: [u8; 2], src1: &[u8; 256]) -> u32 {
    let val = src0[0];

    src1.iter()
        .position(|&byte| byte != val)
        .map_or(256, |len| len as u32)
}

/* 64-bit RLE comparison for hardware with unaligned loads */
#[inline(always)]
fn compare256_rle_64(src0: [u8; 2], src1: &[u8; 256]) -> u32 {
    let src0_cmp = u16::from_ne_bytes(src0);
    let src0_cmp32 = (u32::from(src0_cmp) << 16) | u32::from(src0_cmp);
    let sv = (u64::from(src0_cmp32) << 32) | u64::from(src0_cmp32);
    let mut len = 0;

    for chunk in src1.as_chunks::<8>().0 {
        let mv = u64::from_ne_bytes(*chunk);
        let diff = sv ^ mv;
        if diff != 0 {
            return len + zng_first_diff_byte64(diff);
        }
        len += 8;
    }

    256
}

/// Returns how many bytes of src1 repeat the two bytes of src0, which the caller knows are equal.
#[inline(always)]
pub(crate) fn compare256_rle(src0: [u8; 2], src1: &[u8; 256]) -> u32 {
    if OPTIMAL_CMP == 8 {
        compare256_rle_8(src0, src1)
    } else {
        compare256_rle_64(src0, src1)
    }
}
