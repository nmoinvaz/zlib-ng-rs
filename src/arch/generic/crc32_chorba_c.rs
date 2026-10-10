//! Port of crc32_chorba_c.c.

#[cfg(target_os = "emscripten")]
use core::ffi::c_void;
use core::{ptr, slice};

use crate::arch::generic::crc32_braid_c;
use crate::crc32_braid_tbl::CRC_TABLE;
use crate::crc32_chorba_p::{
    CHORBA_LARGE_THRESHOLD, CHORBA_SMALL_THRESHOLD, CHORBA_W, chorba_word_t,
};
#[cfg(target_pointer_width = "64")]
use crate::crc32_chorba_p::{CHORBA_MEDIUM_LOWER_THRESHOLD, CHORBA_MEDIUM_UPPER_THRESHOLD};
use crate::zbuild::align_diff;

/* Implement Chorba algorithm from https://arxiv.org/abs/2412.16398 */
const BITBUFFER_SIZE_BYTES: usize = 16 * 1024 * size_of::<chorba_word_t>();
const BITBUFFER_SIZE_ZWORDS: usize = BITBUFFER_SIZE_BYTES / size_of::<chorba_word_t>();
const BITBUFFER_SIZE_QWORDS: usize = BITBUFFER_SIZE_BYTES / size_of::<u64>();

/// The alignment lets the buffer be read as 64-bit words when chorba_word_t is narrower.
#[cfg_attr(not(target_os = "emscripten"), repr(C, align(16)))]
#[cfg_attr(target_os = "emscripten", repr(C, align(8)))]
struct BitBuffer([chorba_word_t; BITBUFFER_SIZE_ZWORDS]);

/// Runs f with a zeroed bitbuffer on the stack.
#[cfg(not(target_os = "emscripten"))]
#[inline(always)]
fn with_bitbuffer<R>(f: impl FnOnce(&mut BitBuffer) -> R) -> R {
    f(&mut BitBuffer([0; BITBUFFER_SIZE_ZWORDS]))
}

/// Runs f with a zeroed bitbuffer on the heap, because the Emscripten stack is too small for it.
#[cfg(target_os = "emscripten")]
#[inline(always)]
fn with_bitbuffer<R>(f: impl FnOnce(&mut BitBuffer) -> R) -> R {
    unsafe extern "C" {
        fn malloc(size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);
    }
    // SAFETY: malloc returns memory that is aligned for any 8-byte type. It is zeroed before a
    // reference to it is made, and freed after the last use of that reference.
    unsafe {
        let bitbuffer = malloc(size_of::<BitBuffer>()).cast::<BitBuffer>();
        assert!(!bitbuffer.is_null());
        bitbuffer.write_bytes(0, 1);
        let result = f(&mut *bitbuffer);
        free(bitbuffer.cast());
        result
    }
}

/// Views bytes as native-endian words of type u32 or u64.
///
/// # Safety
///
/// `buf` must start on a boundary that is aligned for `T`.
#[inline(always)]
unsafe fn as_words<T>(buf: &[u8]) -> &[T] {
    debug_assert!(buf.as_ptr().addr().is_multiple_of(align_of::<T>()));
    // SAFETY: the caller guarantees the alignment, the words lie within buf, and every bit pattern
    // is a valid integer.
    unsafe { slice::from_raw_parts(buf.as_ptr().cast::<T>(), buf.len() / size_of::<T>()) }
}

/// Views 64-bit words as bytes.
#[inline(always)]
fn as_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: bytes have no alignment and every byte of an integer is initialized.
    unsafe { slice::from_raw_parts(words.as_ptr().cast::<u8>(), size_of_val(words)) }
}

#[inline(always)]
fn next_round(invec: u64) -> [u64; 4] {
    [
        (invec << 17) ^ (invec << 55),
        (invec >> 47) ^ (invec >> 9) ^ (invec << 19),
        (invec >> 45) ^ (invec << 44),
        invec >> 20,
    ]
}

/// Runs NEXT_ROUND on four words and ACCUM_ROUND on the result. The third word also takes a1 and
/// the fourth takes a2 ^ b1, as every caller of the two macros in the C source does.
#[inline(always)]
fn chorba_fold(input: [u64; 4], next: &mut [u64; 5]) {
    let a = next_round(input[0]);
    let b = next_round(input[1]);
    let c = next_round(input[2] ^ a[0]);
    let d = next_round(input[3] ^ a[1] ^ b[0]);

    *next = [
        next[4] ^ (a[2] ^ b[1] ^ c[0]),
        a[3] ^ b[2] ^ c[1] ^ d[0],
        b[3] ^ c[2] ^ d[1],
        c[3] ^ d[2],
        d[3],
    ];
}

/// One 32-word round of the large variant. Every word takes the matching word of bits, which is
/// zero wherever the pass in the C source has no bitbuffer term.
#[inline(always)]
fn chorba_round(
    input: &[chorba_word_t; 32],
    bits: &[chorba_word_t; 32],
    next: &mut [chorba_word_t; 22],
) -> [chorba_word_t; 32] {
    let in1 = input[0] ^ next[0] ^ bits[0];
    let in2 = input[1] ^ next[1] ^ bits[1];
    let in3 = input[2] ^ next[2] ^ bits[2];
    let in4 = input[3] ^ next[3] ^ bits[3];
    let in5 = input[4] ^ next[4] ^ bits[4];
    let in6 = input[5] ^ next[5] ^ bits[5];
    let in7 = input[6] ^ next[6] ^ bits[6];
    let in8 = input[7] ^ next[7] ^ in1 ^ bits[7];
    let in9 = input[8] ^ next[8] ^ in2 ^ bits[8];
    let in10 = input[9] ^ next[9] ^ in3 ^ bits[9];
    let in11 = input[10] ^ next[10] ^ in4 ^ bits[10];
    let in12 = input[11] ^ next[11] ^ in1 ^ in5 ^ bits[11];
    let in13 = input[12] ^ next[12] ^ in2 ^ in6 ^ bits[12];
    let in14 = input[13] ^ next[13] ^ in3 ^ in7 ^ bits[13];
    let in15 = input[14] ^ next[14] ^ in4 ^ in8 ^ bits[14];
    let in16 = input[15] ^ next[15] ^ in5 ^ in9 ^ bits[15];
    let in17 = input[16] ^ next[16] ^ in6 ^ in10 ^ bits[16];
    let in18 = input[17] ^ next[17] ^ in7 ^ in11 ^ bits[17];
    let in19 = input[18] ^ next[18] ^ in8 ^ in12 ^ bits[18];
    let in20 = input[19] ^ next[19] ^ in9 ^ in13 ^ bits[19];
    let in21 = input[20] ^ next[20] ^ in10 ^ in14 ^ bits[20];
    let in22 = input[21] ^ next[21] ^ in11 ^ in15 ^ bits[21];
    let in23 = input[22] ^ in1 ^ in12 ^ in16 ^ bits[22];
    let in24 = input[23] ^ in2 ^ in13 ^ in17 ^ bits[23];
    let in25 = input[24] ^ in3 ^ in14 ^ in18 ^ bits[24];
    let in26 = input[25] ^ in4 ^ in15 ^ in19 ^ bits[25];
    let in27 = input[26] ^ in5 ^ in16 ^ in20 ^ bits[26];
    let in28 = input[27] ^ in6 ^ in17 ^ in21 ^ bits[27];
    let in29 = input[28] ^ in7 ^ in18 ^ in22 ^ bits[28];
    let in30 = input[29] ^ in8 ^ in19 ^ in23 ^ bits[29];
    let in31 = input[30] ^ in9 ^ in20 ^ in24 ^ bits[30];
    let in32 = input[31] ^ in10 ^ in21 ^ in25 ^ bits[31];

    next[0] = in11 ^ in22 ^ in26;
    next[1] = in12 ^ in23 ^ in27;
    next[2] = in13 ^ in24 ^ in28;
    next[3] = in14 ^ in25 ^ in29;
    next[4] = in15 ^ in26 ^ in30;
    next[5] = in16 ^ in27 ^ in31;
    next[6] = in17 ^ in28 ^ in32;
    next[7] = in18 ^ in29;
    next[8] = in19 ^ in30;
    next[9] = in20 ^ in31;
    next[10] = in21 ^ in32;
    next[11] = in22;
    next[12] = in23;
    next[13] = in24;
    next[14] = in25;
    next[15] = in26;
    next[16] = in27;
    next[17] = in28;
    next[18] = in29;
    next[19] = in30;
    next[20] = in31;
    next[21] = in32;

    [
        in1, in2, in3, in4, in5, in6, in7, in8, in9, in10, in11, in12, in13, in14, in15, in16,
        in17, in18, in19, in20, in21, in22, in23, in24, in25, in26, in27, in28, in29, in30, in31,
        in32,
    ]
}

/// Stores the words of a round where a round 14870 words later reads them back.
#[inline(always)]
fn chorba_store(bitbuffer: &mut BitBuffer, w: usize, words: &[chorba_word_t; 32]) {
    let out_offset1 = (w + 14848) % BITBUFFER_SIZE_ZWORDS;
    let out_offset2 = (w + 14880) % BITBUFFER_SIZE_ZWORDS;
    let blocks = bitbuffer.0.as_chunks_mut::<32>().0;

    blocks[out_offset1 / 32][22..].copy_from_slice(&words[..10]);
    blocks[out_offset2 / 32][..22].copy_from_slice(&words[10..]);
}

/// Copies the bytes after position i into a zeroed block and folds next into its first words.
#[inline(always)]
fn chorba_final(buf: &[u8], i: usize, next: &[u64; 5]) -> ([u8; 72], usize) {
    let rest = buf.get(i..).unwrap_or_default();
    let len = rest.len().min(72);
    let mut block = [0; 72];
    block[..len].copy_from_slice(&rest[..len]);
    for (word, next) in block.as_chunks_mut::<8>().0.iter_mut().zip(next) {
        *word = (u64::from_ne_bytes(*word) ^ next.to_le()).to_ne_bytes();
    }
    (block, len)
}

/// Folds the rest of the input 32 bytes at a time while pulling the matching words out of the
/// bitbuffer, then finishes the last bytes with the table.
#[inline(always)]
fn chorba_finish(buf: &[u8], input: &[u64], bitbuffer: &[u64], mut i: usize) -> u32 {
    let bitbuffer_bytes = as_bytes(bitbuffer);
    let input = input.as_chunks::<4>().0;
    let bitbuffer = bitbuffer.as_chunks::<4>().0;
    let mut next = [0; 5];

    while i + 72 < buf.len() {
        let Some(input) = input.get(i / 32) else {
            break;
        };
        let bits = bitbuffer[(i / 32) % bitbuffer.len()];
        chorba_fold(
            [
                u64::from_le(input[0] ^ bits[0]) ^ next[0],
                u64::from_le(input[1] ^ bits[1]) ^ next[1],
                u64::from_le(input[2] ^ bits[2]) ^ next[2],
                u64::from_le(input[3] ^ bits[3]) ^ next[3],
            ],
            &mut next,
        );
        i += 32;
    }

    let (block, len) = chorba_final(buf, i, &next);
    let mut crc = 0;
    for (j, &byte) in block[..len].iter().enumerate() {
        let bits = bitbuffer_bytes[(j + i) % bitbuffer_bytes.len()];
        crc = CRC_TABLE[usize::from(crc as u8 ^ byte ^ bits)] ^ (crc >> 8);
    }

    !crc
}

/**
 * Implements the Chorba algorithm for CRC32 computation (https://arxiv.org/abs/2412.16398).
 *
 * This implementation processes data in three phases:
 * 1. Initial pass: Zeros out bitbuffer
 * 2. Intermediate pass: Processes half the values
 * 3. Main pass: Processes remaining data
 *
 * @param crc Initial CRC value
 * @param input Input data buffer
 * @param len Length of input data
 * @return Computed CRC32 value
 *
 * @note Requires minimum input size of 118960 + 512 bytes
 * @note Uses 128KB temporary buffer
 */
/// # Safety
///
/// `buf` must start on an 8-byte boundary.
unsafe fn chorba_118960_nondestructive(crc: u32, buf: &[u8]) -> u32 {
    /* The calling function ensured that this is aligned correctly */
    // SAFETY: the caller guarantees an 8-byte boundary, which is aligned for both word types.
    let (input, input_qwords) = unsafe { (as_words::<chorba_word_t>(buf), as_words::<u64>(buf)) };
    let mut input = input.as_chunks::<32>().0.iter();

    with_bitbuffer(|bitbuffer| {
        let mut w = 0;
        let mut next = [0; 22];
        next[0] = chorba_word_t::from_le(chorba_word_t::from(!crc));

        // do a first pass to zero out bitbuffer
        while w < 14848 {
            let Some(input) = input.next() else { break };
            let words = chorba_round(input, &[0; 32], &mut next);
            chorba_store(bitbuffer, w, &words);
            w += 32;
        }

        // one intermediate pass where we pull half the values
        while w < 14880 {
            let Some(input) = input.next() else { break };
            let in_offset = w % BITBUFFER_SIZE_ZWORDS;
            let mut bits = [0; 32];
            bits[22..].copy_from_slice(&bitbuffer.0.as_chunks::<32>().0[in_offset / 32][22..]);
            let words = chorba_round(input, &bits, &mut next);
            chorba_store(bitbuffer, w, &words);
            w += 32;
        }

        while (w + 14870 + 64) * CHORBA_W < buf.len() {
            let Some(input) = input.next() else { break };
            let in_offset = w % BITBUFFER_SIZE_ZWORDS;
            let bits = bitbuffer.0.as_chunks::<32>().0[in_offset / 32];
            let words = chorba_round(input, &bits, &mut next);
            chorba_store(bitbuffer, w, &words);
            w += 32;
        }

        for (k, &next) in next.iter().enumerate() {
            bitbuffer.0[(w + k) % BITBUFFER_SIZE_ZWORDS] ^= next;
        }

        for j in 14870..14870 + 64 {
            bitbuffer.0[(j + w) % BITBUFFER_SIZE_ZWORDS] = 0;
        }

        // SAFETY: the bitbuffer is aligned for u64 and holds BITBUFFER_SIZE_QWORDS of them.
        let bitbuffer_qwords = unsafe {
            slice::from_raw_parts(bitbuffer.0.as_ptr().cast::<u64>(), BITBUFFER_SIZE_QWORDS)
        };
        chorba_finish(buf, input_qwords, bitbuffer_qwords, w * CHORBA_W)
    })
}

/// The offsets 145, 183 and 211 that the medium variant folds into are odd, so the words start on
/// an odd 8-byte boundary to keep the 16-byte loads and stores at those offsets aligned.
#[cfg(target_pointer_width = "64")]
#[repr(C, align(16))]
struct MediumBitBuffer {
    _pad: u64,
    words: [u64; 32768 / size_of::<u64>()],
}

/* Implement Chorba algorithm from https://arxiv.org/abs/2412.16398 */
/// # Safety
///
/// `buf` must start on an 8-byte boundary.
#[cfg(target_pointer_width = "64")]
unsafe fn chorba_32768_nondestructive(crc: u32, buf: &[u8]) -> u32 {
    /* The calling function ensured that this is aligned correctly */
    // SAFETY: the caller guarantees an 8-byte boundary.
    let input = unsafe { as_words::<u64>(buf) };
    let mut bitbuffer = MediumBitBuffer {
        _pad: 0,
        words: [0; 32768 / size_of::<u64>()],
    };
    let bitbuffer = &mut bitbuffer.words;
    bitbuffer[0] = u64::from(!crc).to_le();

    let mut i = 0;

    for input in input.as_chunks::<8>().0 {
        if i + 300 * 8 + 64 >= buf.len() {
            break;
        }
        let Some(bits) = bitbuffer.get_mut(i / 8..i / 8 + 308) else {
            break;
        };
        let mut words = [0; 8];
        for k in 0..8 {
            words[k] = input[k] ^ bits[k];
        }

        // [0, 145, 183, 211]

        for k in 0..8 {
            bits[k + 145] ^= words[k];
        }

        for k in 0..8 {
            bits[k + 183] ^= words[k];
        }

        for k in 0..8 {
            bits[k + 211] ^= words[k];
        }

        bits[300..].copy_from_slice(&words);
        i += 64;
    }

    chorba_finish(buf, input, bitbuffer, i)
}

/* Implement Chorba algorithm from https://arxiv.org/abs/2412.16398 */
/// # Safety
///
/// `buf` must start on an 8-byte boundary.
#[cfg(target_pointer_width = "64")]
unsafe fn chorba_small_nondestructive(crc: u32, buf: &[u8]) -> u32 {
    /* The calling function ensured that this is aligned correctly */
    // SAFETY: the caller guarantees an 8-byte boundary.
    let input = unsafe { as_words::<u64>(buf) };
    let mut next = [u64::from(!crc), 0, 0, 0, 0];

    let mut i = 0;

    /* This is weird, doing for vs while drops 10% off the exec time */
    while i + 256 + 40 + 32 + 32 < buf.len() {
        let Some(input) = input.as_chunks::<40>().0.get(i / 320) else {
            break;
        };
        let le = |k: usize| u64::from_le(input[k]);

        let chorba1 = le(0) ^ next[0];
        let chorba2 = le(1) ^ next[1];
        let chorba3 = le(2) ^ next[2];
        let chorba4 = le(3) ^ next[3];
        let chorba5 = le(4) ^ next[4];
        let chorba6 = le(5);
        let chorba7 = le(6) ^ chorba1;
        let chorba8 = le(7) ^ chorba2;

        /* 0-3 */
        /* chorba5 already consumed next5, clear it so ACCUM_ROUND
        does not xor the stale value into next1 */
        next[4] = 0;
        chorba_fold(
            [
                le(8) ^ chorba3,
                le(9) ^ chorba4 ^ chorba1,
                le(10) ^ chorba5 ^ chorba2 ^ chorba1,
                le(11) ^ chorba6 ^ chorba3 ^ chorba2,
            ],
            &mut next,
        );

        /* 4-7 */
        chorba_fold(
            [
                le(12) ^ next[0] ^ chorba7 ^ chorba4 ^ chorba3,
                le(13) ^ next[1] ^ chorba8 ^ chorba5 ^ chorba4,
                le(14) ^ next[2] ^ chorba6 ^ chorba5,
                le(15) ^ next[3] ^ chorba7 ^ chorba6,
            ],
            &mut next,
        );

        /* 8-11 */
        chorba_fold(
            [
                le(16) ^ next[0] ^ chorba8 ^ chorba7 ^ chorba1,
                le(17) ^ next[1] ^ chorba8 ^ chorba2,
                le(18) ^ next[2] ^ chorba3,
                le(19) ^ next[3] ^ chorba4,
            ],
            &mut next,
        );

        /* 12-15 */
        chorba_fold(
            [
                le(20) ^ next[0] ^ chorba5 ^ chorba1,
                le(21) ^ next[1] ^ chorba6 ^ chorba2 ^ chorba1,
                le(22) ^ next[2] ^ chorba7 ^ chorba3 ^ chorba2 ^ chorba1,
                le(23) ^ next[3] ^ chorba8 ^ chorba4 ^ chorba3 ^ chorba2,
            ],
            &mut next,
        );

        /* 16-19 */
        chorba_fold(
            [
                le(24) ^ next[0] ^ chorba5 ^ chorba4 ^ chorba3 ^ chorba1,
                le(25) ^ next[1] ^ chorba6 ^ chorba5 ^ chorba4 ^ chorba1 ^ chorba2,
                le(26) ^ next[2] ^ chorba7 ^ chorba6 ^ chorba5 ^ chorba2 ^ chorba3,
                le(27) ^ next[3] ^ chorba8 ^ chorba7 ^ chorba6 ^ chorba3 ^ chorba4 ^ chorba1,
            ],
            &mut next,
        );

        /* 20-23 */
        chorba_fold(
            [
                le(28) ^ next[0] ^ chorba8 ^ chorba7 ^ chorba4 ^ chorba5 ^ chorba2 ^ chorba1,
                le(29) ^ next[1] ^ chorba8 ^ chorba5 ^ chorba6 ^ chorba3 ^ chorba2,
                le(30) ^ next[2] ^ chorba7 ^ chorba6 ^ chorba4 ^ chorba3 ^ chorba1,
                le(31) ^ next[3] ^ chorba8 ^ chorba7 ^ chorba5 ^ chorba4 ^ chorba2 ^ chorba1,
            ],
            &mut next,
        );

        /* 24-27 */
        chorba_fold(
            [
                le(32) ^ next[0] ^ chorba8 ^ chorba6 ^ chorba5 ^ chorba3 ^ chorba2 ^ chorba1,
                le(33) ^ next[1] ^ chorba7 ^ chorba6 ^ chorba4 ^ chorba3 ^ chorba2,
                le(34) ^ next[2] ^ chorba8 ^ chorba7 ^ chorba5 ^ chorba4 ^ chorba3,
                le(35) ^ next[3] ^ chorba8 ^ chorba6 ^ chorba5 ^ chorba4,
            ],
            &mut next,
        );

        /* 28-31 */
        chorba_fold(
            [
                le(36) ^ next[0] ^ chorba7 ^ chorba6 ^ chorba5,
                le(37) ^ next[1] ^ chorba8 ^ chorba7 ^ chorba6,
                le(38) ^ next[2] ^ chorba8 ^ chorba7,
                le(39) ^ next[3] ^ chorba8,
            ],
            &mut next,
        );

        i += 320;
    }

    while i + 40 + 32 < buf.len() {
        let Some(input) = input.as_chunks::<4>().0.get(i / 32) else {
            break;
        };
        chorba_fold(
            [
                u64::from_le(input[0]) ^ next[0],
                u64::from_le(input[1]) ^ next[1],
                u64::from_le(input[2]) ^ next[2],
                u64::from_le(input[3]) ^ next[3],
            ],
            &mut next,
        );
        i += 32;
    }

    let (block, len) = chorba_final(buf, i, &next);
    crc32_braid_c::crc32(!0, &block[..len])
}

/// The six shifted values that one word contributes to the words after it
#[cfg(not(target_pointer_width = "64"))]
struct Round32 {
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    r6: u32,
    r7: u32,
}

#[cfg(not(target_pointer_width = "64"))]
#[inline(always)]
fn next_round32(invec: u32) -> Round32 {
    Round32 {
        r1: invec << 17,
        r2: (invec >> 15) ^ (invec << 23),
        r3: (invec >> 9) ^ (invec << 19),
        r4: invec >> 13,
        r6: invec << 12,
        r7: invec >> 20,
    }
}

/// # Safety
///
/// `buf` must start on a 4-byte boundary.
#[cfg(not(target_pointer_width = "64"))]
unsafe fn chorba_small_nondestructive_32bit(crc: u32, buf: &[u8]) -> u32 {
    /* The calling function ensured that this is aligned correctly */
    // SAFETY: the caller guarantees a 4-byte boundary.
    let input = unsafe { as_words::<u32>(buf) };
    let mut next = [0u32; 10];
    next[0] = !crc;

    let mut i = 0;
    while i + 80 < buf.len() {
        let Some(input) = input.as_chunks::<10>().0.get(i / 40) else {
            break;
        };
        let le = |k: usize| u32::from_le(input[k]);

        let in1 = le(0) ^ next[0];
        let in2 = le(1) ^ next[1];
        let in3 = le(2) ^ next[2];
        let in4 = le(3) ^ next[3];

        let a = next_round32(in1);
        let b = next_round32(in2);
        let c = next_round32(in3);
        let d = next_round32(in4);

        let in5 = le(4) ^ next[4] ^ a.r1;
        let in6 = le(5) ^ next[5] ^ a.r2 ^ b.r1;
        let in7 = le(6) ^ next[6] ^ a.r3 ^ b.r2 ^ c.r1;
        let in8 = le(7) ^ next[7] ^ a.r4 ^ b.r3 ^ c.r2 ^ d.r1;

        let e = next_round32(in5);
        let f = next_round32(in6);
        let g = next_round32(in7);
        let h = next_round32(in8);

        let in9 = le(8) ^ next[8] ^ b.r4 ^ c.r3 ^ d.r2 ^ e.r1;
        let in10 = le(9) ^ next[9] ^ a.r6 ^ c.r4 ^ d.r3 ^ e.r2 ^ f.r1;

        let i_ = next_round32(in9);
        let j = next_round32(in10);

        next = [
            a.r7 ^ b.r6 ^ d.r4 ^ e.r3 ^ f.r2 ^ g.r1,
            b.r7 ^ c.r6 ^ e.r4 ^ f.r3 ^ g.r2 ^ h.r1,
            c.r7 ^ d.r6 ^ f.r4 ^ g.r3 ^ h.r2 ^ i_.r1,
            d.r7 ^ e.r6 ^ g.r4 ^ h.r3 ^ i_.r2 ^ j.r1,
            e.r7 ^ f.r6 ^ h.r4 ^ i_.r3 ^ j.r2,
            f.r7 ^ g.r6 ^ i_.r4 ^ j.r3,
            g.r7 ^ h.r6 ^ j.r4,
            h.r7 ^ i_.r6,
            i_.r7 ^ j.r6,
            j.r7,
        ];

        i += 40;
    }

    let rest = buf.get(i..).unwrap_or_default();
    let len = rest.len().min(80);
    let mut block = [0u8; 80];
    block[..len].copy_from_slice(&rest[..len]);
    for (word, next) in block.as_chunks_mut::<4>().0.iter_mut().zip(next) {
        *word = (u32::from_ne_bytes(*word) ^ next.to_le()).to_ne_bytes();
    }

    crc32_braid_c::crc32(!0, &block[..len])
}

pub(crate) fn crc32(mut crc: u32, buf: &[u8]) -> u32 {
    let align_diff = align_diff(buf.as_ptr(), 8);
    if buf.len() <= align_diff + CHORBA_SMALL_THRESHOLD {
        return crc32_braid_c::crc32(crc, buf);
    }

    let (head, buf) = buf.split_at(align_diff);
    if !head.is_empty() {
        crc = crc32_braid_c::crc32(crc, head);
    }
    // SAFETY: buf starts on an 8-byte boundary now.
    unsafe {
        if buf.len() > CHORBA_LARGE_THRESHOLD {
            return chorba_118960_nondestructive(crc, buf);
        }
        #[cfg(target_pointer_width = "64")]
        {
            if buf.len() > CHORBA_MEDIUM_LOWER_THRESHOLD
                && buf.len() <= CHORBA_MEDIUM_UPPER_THRESHOLD
            {
                return chorba_32768_nondestructive(crc, buf);
            }
            chorba_small_nondestructive(crc, buf)
        }
        #[cfg(not(target_pointer_width = "64"))]
        chorba_small_nondestructive_32bit(crc, buf)
    }
}

/// # Safety
///
/// `buf` must be valid for reads of `len` bytes and start on an 8-byte boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crc32_chorba_118960_nondestructive(
    crc: u32,
    buf: *const u8,
    len: usize,
) -> u32 {
    // SAFETY: the caller guarantees buf is valid for reads of len bytes and aligned.
    unsafe { chorba_118960_nondestructive(crc, slice::from_raw_parts(buf, len)) }
}

/// # Safety
///
/// `buf` must be valid for reads of `len` bytes and start on an 8-byte boundary.
#[cfg(target_pointer_width = "64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crc32_chorba_32768_nondestructive(
    crc: u32,
    buf: *const u8,
    len: usize,
) -> u32 {
    // SAFETY: the caller guarantees buf is valid for reads of len bytes and aligned.
    unsafe { chorba_32768_nondestructive(crc, slice::from_raw_parts(buf, len)) }
}

/// # Safety
///
/// `buf` must be valid for reads of `len` bytes and start on an 8-byte boundary.
#[cfg(target_pointer_width = "64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crc32_chorba_small_nondestructive(
    crc: u32,
    buf: *const u8,
    len: usize,
) -> u32 {
    // SAFETY: the caller guarantees buf is valid for reads of len bytes and aligned.
    unsafe { chorba_small_nondestructive(crc, slice::from_raw_parts(buf, len)) }
}

/// # Safety
///
/// `buf` must be valid for reads of `len` bytes and start on a 4-byte boundary.
#[cfg(not(target_pointer_width = "64"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crc32_chorba_small_nondestructive_32bit(
    crc: u32,
    buf: *const u8,
    len: usize,
) -> u32 {
    // SAFETY: the caller guarantees buf is valid for reads of len bytes and aligned.
    unsafe { chorba_small_nondestructive_32bit(crc, slice::from_raw_parts(buf, len)) }
}

/// # Safety
///
/// `buf` must be valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crc32_chorba(crc: u32, buf: *const u8, len: usize) -> u32 {
    if len == 0 {
        return crc32(crc, &[]);
    }
    // SAFETY: the caller guarantees buf is valid for reads of len bytes.
    crc32(crc, unsafe { slice::from_raw_parts(buf, len) })
}

/// # Safety
///
/// `src` must be valid for reads of `len` bytes, `dst` must be valid for writes of `len` bytes,
/// and the two must not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crc32_copy_chorba(
    crc: u32,
    dst: *mut u8,
    src: *const u8,
    len: usize,
) -> u32 {
    // SAFETY: the caller guarantees src is valid for reads of len bytes.
    let crc = unsafe { crc32_chorba(crc, src, len) };
    if len != 0 {
        // SAFETY: the caller guarantees both ranges are valid and do not overlap.
        unsafe { ptr::copy_nonoverlapping(src, dst, len) };
    }
    crc
}
