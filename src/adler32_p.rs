//! adler32_p.h -- Private inline functions and macros shared with
//!                different computation of the Adler-32 checksum
//!                of a data stream.
//! Copyright (C) 1995-2011, 2016 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

use core::slice;

/// largest prime smaller than 65536
pub(crate) const BASE: u32 = 65521;
/// NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1
pub(crate) const NMAX: usize = 5552;
/// NMAX rounded down to a multiple of 8 is 5552
pub(crate) const NMAX_ALIGNED8: usize = NMAX & !7;

#[inline(always)]
fn adler_do1(sum1: &mut u32, sum2: &mut u32, byte: u8) {
    *sum1 += u32::from(byte);
    *sum2 += *sum1;
}

#[inline(always)]
fn adler_do2(sum1: &mut u32, sum2: &mut u32, buf: [u8; 2]) {
    adler_do1(sum1, sum2, buf[0]);
    adler_do1(sum1, sum2, buf[1]);
}

#[inline(always)]
fn adler_do4(sum1: &mut u32, sum2: &mut u32, buf: [u8; 4]) {
    adler_do2(sum1, sum2, [buf[0], buf[1]]);
    adler_do2(sum1, sum2, [buf[2], buf[3]]);
}

#[inline(always)]
pub(crate) fn adler32_copy_align(adler: &mut u32, buf: &[u8], sum2: &mut u32) {
    let mut buf = buf;
    if buf.len() & 1 != 0
        && let Some((&byte, rest)) = buf.split_first()
    {
        adler_do1(adler, sum2, byte);
        buf = rest;
    }
    if buf.len() & 2 != 0
        && let Some((&pair, rest)) = buf.split_first_chunk::<2>()
    {
        adler_do2(adler, sum2, pair);
        buf = rest;
    }
    for &quad in buf.as_chunks::<4>().0 {
        adler_do4(adler, sum2, quad);
    }
}

/* SIMD Within A Register (SWAR) scalar adler32. Splits bytes into
 * even/odd lanes packed as 4x16-bit in uint64_t, with prefix sums for s2.
 * Reduction uses multiply-and-shift with positional weight constants.
 *
 * Technique pioneered by Michael Niedermayer <michaelni@gmx.at>.
 * Max chunk: 23 iterations * 8 bytes = 184 (255*23 = 5865 < 65535). */
pub(crate) const ADLER32_SWAR_MAX_BYTES: usize = 23 * 8;
const ADLER32_SWAR_EVEN_MASK: u64 = 0x00FF00FF00FF00FF;
const ADLER32_SWAR_HSUM: u64 = 0x1000100010001;

#[inline(always)]
fn adler32_swar(adler: &mut u32, words: &[u64], sum2: &mut u32) {
    let (mut sum_even, mut sum_odd, mut prefix_even, mut prefix_odd) = (0u64, 0u64, 0u64, 0u64);

    *sum2 += *adler * (words.len() * 8) as u32;

    let (pairs, last) = words.as_chunks::<2>();

    for &[v0, v1] in pairs {
        prefix_even += sum_even;
        prefix_odd += sum_odd;
        sum_even += v0 & ADLER32_SWAR_EVEN_MASK;
        sum_odd += (v0 >> 8) & ADLER32_SWAR_EVEN_MASK;

        prefix_even += sum_even;
        prefix_odd += sum_odd;
        sum_even += v1 & ADLER32_SWAR_EVEN_MASK;
        sum_odd += (v1 >> 8) & ADLER32_SWAR_EVEN_MASK;
    }

    /* Handle remaining 8 bytes if present */
    if let &[v] = last {
        prefix_even += sum_even;
        prefix_odd += sum_odd;
        sum_even += v & ADLER32_SWAR_EVEN_MASK;
        sum_odd += (v >> 8) & ADLER32_SWAR_EVEN_MASK;
    }

    /* Horizontal sum of 4x16-bit lanes for s1 */
    *adler += ((sum_even + sum_odd).wrapping_mul(ADLER32_SWAR_HSUM) >> 48) as u32;

    /* Widen prefix sums to 32-bit pairs and horizontal sum for s2 */
    let pe_lo = prefix_even & 0xFFFF0000FFFF;
    let pe_hi = (prefix_even >> 16) & 0xFFFF0000FFFF;
    let po_lo = prefix_odd & 0xFFFF0000FFFF;
    let po_hi = (prefix_odd >> 16) & 0xFFFF0000FFFF;

    *sum2 += ((pe_lo + po_lo + pe_hi + po_hi).wrapping_mul(0x800000008) >> 32) as u32;

    /* Positional weights [8,7,6,5,4,3,2,1] per 8-byte group for s2.
     * On big-endian the even mask captures odd-index memory bytes (b1,b3,b5,b7)
     * so HSUM (+1 per odd-index byte) must be applied to sum_even, not sum_odd. */
    if cfg!(target_endian = "little") {
        *sum2 += 2 * (sum_even.wrapping_mul(0x4000300020001) >> 48) as u32
            + (sum_odd.wrapping_mul(ADLER32_SWAR_HSUM) >> 48) as u32
            + 2 * (sum_odd.wrapping_mul(0x3000200010000) >> 48) as u32;
    } else {
        *sum2 += 2 * (sum_even.wrapping_mul(0x0000100020003) >> 48) as u32
            + (sum_even.wrapping_mul(ADLER32_SWAR_HSUM) >> 48) as u32
            + 2 * (sum_odd.wrapping_mul(0x1000200030004) >> 48) as u32;
    }
}

/// Runs the SWAR sums over the 8-byte words of buf when it starts on an 8-byte boundary and
/// returns the bytes that follow them.
#[inline(always)]
pub(crate) fn adler32_swar_words<'a>(adler: &mut u32, buf: &'a [u8], sum2: &mut u32) -> &'a [u8] {
    if buf.as_ptr().addr() & 7 != 0 {
        return buf;
    }
    let (chunks, rest) = buf.as_chunks::<8>();
    // SAFETY: chunks starts on an 8-byte boundary and every bit pattern is a valid u64.
    let words = unsafe { slice::from_raw_parts(chunks.as_ptr().cast::<u64>(), chunks.len()) };
    for chunk in words.chunks(ADLER32_SWAR_MAX_BYTES / 8) {
        adler32_swar(adler, chunk, sum2);
    }
    rest
}

#[inline(always)]
pub(crate) fn adler32_copy_tail(mut adler: u32, buf: &[u8], mut sum2: u32, rebase: bool) -> u32 {
    /* Process using packed 64-bit arithmetic when source is aligned */
    let buf = adler32_swar_words(&mut adler, buf, &mut sum2);
    /* DO4 loop avoids GCC x86 register pressure from hoisted DO8/DO16 loads. */
    let (quads, mut buf) = buf.as_chunks::<4>();
    for &quad in quads {
        adler_do4(&mut adler, &mut sum2, quad);
    }
    if buf.len() & 2 != 0
        && let Some((&pair, rest)) = buf.split_first_chunk::<2>()
    {
        adler_do2(&mut adler, &mut sum2, pair);
        buf = rest;
    }
    if let Some(&byte) = buf.first() {
        adler_do1(&mut adler, &mut sum2, byte);
    }
    if rebase {
        adler %= BASE;
        sum2 %= BASE;
    }
    /* D = B * 65536 + A, see: https://en.wikipedia.org/wiki/Adler-32. */
    adler | (sum2 << 16)
}
