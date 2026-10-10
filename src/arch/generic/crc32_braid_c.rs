//! crc32_braid.c -- compute the CRC-32 of a data stream
//! Copyright (C) 1995-2022 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h
//!
//! This interleaved implementation of a CRC makes use of pipelined multiple
//! arithmetic-logic units, commonly found in modern CPU cores. It is due to
//! Kadatch and Jenkins (2010). See doc/crc-doc.1.0.pdf in this distribution.

use core::{ptr, slice};

use crate::crc32_braid_p::{BRAID_N, BRAID_W, z_word_t};
#[cfg(target_endian = "big")]
use crate::crc32_braid_tbl::CRC_BIG_TABLE;
#[cfg(target_endian = "little")]
use crate::crc32_braid_tbl::CRC_TABLE;
use crate::crc32_braid_tbl::braid_table;
use crate::crc32_p::crc32_copy_small;
use crate::zbuild::align_diff;

/*
  A CRC of a message is computed on BRAID_N braids of words in the message, where
  each word consists of BRAID_W bytes (4 or 8). If BRAID_N is 3, for example, then
  three running sparse CRCs are calculated respectively on each braid, at these
  indices in the array of words: 0, 3, 6, ..., 1, 4, 7, ..., and 2, 5, 8, ...
  This is done starting at a word boundary, and continues until as many blocks of
  BRAID_N * BRAID_W bytes as are available have been processed. The results are
  combined into a single CRC at the end. For this code, BRAID_N must be in the
  range 1..6 and BRAID_W must be 4 or 8. The upper limit on BRAID_N can be increased
  if desired by adding more #if blocks, extending the patterns apparent in the code.
  In addition, crc32 tables would need to be regenerated, if the maximum BRAID_N
  value is increased.

  BRAID_N and BRAID_W are chosen empirically by benchmarking the execution time
  on a given processor. The choices for BRAID_N and BRAID_W below were based on
  testing on Intel Kaby Lake i7, AMD Ryzen 7, ARM Cortex-A57, Sparc64-VII, PowerPC
  POWER9, and MIPS64 Octeon II processors.
  The Intel, AMD, and ARM processors were all fastest with BRAID_N=5, BRAID_W=8.
  The Sparc, PowerPC, and MIPS64 were all fastest at BRAID_N=5, BRAID_W=4.
  They were all tested with either gcc or clang, all using the -O3 optimization
  level. Your mileage may vary.
*/

/* ========================================================================= */
/*
  Return the CRC of the BRAID_W bytes in the word_t data, taking the
  least-significant byte of the word as the first byte of data, without any pre
  or post conditioning. This is used to combine the CRCs of each braid.
*/
#[cfg(target_endian = "little")]
#[inline(always)]
fn crc_word(mut data: z_word_t) -> z_word_t {
    for _ in 0..BRAID_W {
        data = (data >> 8) ^ z_word_t::from(CRC_TABLE[usize::from(data as u8)]);
    }
    z_word_t::from(data as u32)
}

#[cfg(target_endian = "big")]
#[inline(always)]
fn crc_word(mut data: z_word_t) -> z_word_t {
    for _ in 0..BRAID_W {
        data = (data << 8) ^ CRC_BIG_TABLE[usize::from((data >> ((BRAID_W - 1) << 3)) as u8)];
    }
    data
}

/* ========================================================================= */
pub(crate) fn crc32(crc: u32, buf: &[u8]) -> u32 {
    let mut crc = !crc;
    let mut buf = buf;

    /* If provided enough bytes, do a braided CRC calculation. */
    if buf.len() >= BRAID_N * BRAID_W + BRAID_W - 1 {
        /* Compute the CRC up to a z_word_t boundary. */
        let (head, rest) = buf.split_at(align_diff(buf.as_ptr(), BRAID_W).min(buf.len()));
        crc = crc32_copy_small::<{ BRAID_W - 1 }>(crc, head);

        /* Compute the CRC on as many BRAID_N z_word_t blocks as are available. */
        let (blocks, rest) = rest.as_chunks::<{ BRAID_N * BRAID_W }>();
        // SAFETY: blocks starts on a z_word_t boundary, each block is BRAID_N words long, and every
        // bit pattern is a valid z_word_t.
        let blocks = unsafe {
            slice::from_raw_parts(blocks.as_ptr().cast::<[z_word_t; BRAID_N]>(), blocks.len())
        };

        if let Some((last, blocks)) = blocks.split_last() {
            /* Initialize the CRC for each braid. */
            let mut crcs = [0; BRAID_N];
            crcs[0] = z_word_t::from_le(z_word_t::from(crc));

            /* Process the first blks-1 blocks, computing the CRCs on each braid independently. */
            for block in blocks {
                /* Load the word for each braid into registers. */
                let mut words = [0; BRAID_N];
                for n in 0..BRAID_N {
                    words[n] = crcs[n] ^ block[n];
                }

                /* Compute and update the CRC for each word. The loop should get unrolled. */
                for n in 0..BRAID_N {
                    crcs[n] = braid_table(0, words[n] as u8);
                }
                for k in 1..BRAID_W {
                    for n in 0..BRAID_N {
                        crcs[n] ^= braid_table(k, (words[n] >> (k << 3)) as u8);
                    }
                }
            }

            /* Process the last block, combining the CRCs of the BRAID_N braids at the same time. */
            let mut comb = 0;
            for n in 0..BRAID_N {
                comb = crc_word(crcs[n] ^ last[n] ^ comb);
            }
            crc = z_word_t::from_le(comb) as u32;

            /* Update the pointer to the remaining bytes to process. */
            buf = rest;
        }
    }

    /* Complete the computation of the CRC on any remaining bytes. */
    !crc32_copy_small::<{ BRAID_N * BRAID_W - 1 }>(crc, buf)
}

/// # Safety
///
/// `buf` must be valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crc32_braid(crc: u32, buf: *const u8, len: usize) -> u32 {
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
pub unsafe extern "C" fn crc32_copy_braid(
    crc: u32,
    dst: *mut u8,
    src: *const u8,
    len: usize,
) -> u32 {
    // SAFETY: the caller guarantees src is valid for reads of len bytes.
    let crc = unsafe { crc32_braid(crc, src, len) };
    if len != 0 {
        // SAFETY: the caller guarantees both ranges are valid and do not overlap.
        unsafe { ptr::copy_nonoverlapping(src, dst, len) };
    }
    crc
}
