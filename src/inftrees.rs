//! inftrees.c -- generate Huffman trees for efficient decoding
//! Copyright (C) 1995-2026 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

/* WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change. Applications should only use zlib.h.
*/

use core::ffi::c_uint;

use crate::inflate_p::{combine_bits, combine_op};
use crate::zbuild::{likely, prefix, unlikely};
use crate::zmemory::zng_memwrite_4;
use crate::zutil::MAX_BITS;

/* Structure for decoding tables.  Each entry provides either the
information needed to do the operation requested by the code that
indexed that table entry, or it provides a pointer to another
table that indexes more bits of the code.  op indicates whether
the entry is a pointer to another table, a literal, a length or
distance, an end-of-block, or an invalid code.  For a table
pointer, the low four bits of op is the number of index bits of
that table.  For a length or distance, the low four bits of op
is the number of extra bits to get after the code.  bits is
the number of bits in this code or part of the code to drop off
of the bit buffer.  val is the actual byte to output in the case
of a literal, the base length or distance, or the offset from
the current table to the next table.  Each entry is four bytes. */
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct code {
    /// bits in this part of the code
    pub bits: u8,
    /// operation, extra bits, table bits
    pub op: u8,
    /// offset in table or code value
    pub val: u16,
}

/* op values as set by inflate_table():
   00000000 - literal
   0000tttt - table link, tttt != 0 is the number of table index bits
   0001eeee - length or distance, eeee is the number of non-extra bits
   01100000 - end of block
   01000000 - invalid code
*/

/* Maximum size of the dynamic table.  The maximum number of code structures is
1924, which is the sum of 1332 for literal/length codes and 592 for distance
codes.  These values were found by exhaustive searches using the program
examples/enough.c found in the zlib distributions.  The arguments to that
program are the number of symbols, the initial root table size, and the
maximum bit length of a code.  "enough 286 10 15" for literal/length codes
returns 1332, and "enough 30 9 15" for distance codes returns 592.
The initial root table size (10 or 9) is found in the fifth argument of the
inflate_table() calls in inflate.c and infback.c.  If the root table size is
changed, then these maximum sizes would be need to be recalculated and
updated. */
pub(crate) const ENOUGH_LENS: usize = 1332;
pub(crate) const ENOUGH_DISTS: usize = 592;
pub(crate) const ENOUGH: usize = ENOUGH_LENS + ENOUGH_DISTS;

/// Type of code to build for inflate_table()
#[allow(non_camel_case_types)]
pub type codetype = c_uint;
pub const CODES: codetype = 0;
pub const LENS: codetype = 1;
pub const DISTS: codetype = 2;

/// If you use the zlib library in a product, an acknowledgment is welcome
/// in the documentation of your product. If for some reason you cannot
/// include such an acknowledgment, I would appreciate that you keep this
/// copyright string in the executable of your product.
const COPYRIGHT: &[u8] = b" inflate 1.3.2 Copyright 1995-2026 Mark Adler \0";

#[allow(non_upper_case_globals)]
#[used]
#[unsafe(export_name = prefix!("inflate_copyright"))]
pub static inflate_copyright: [u8; COPYRIGHT.len()] = {
    let mut text = [0; COPYRIGHT.len()];
    let mut i = 0;
    while i < text.len() {
        text[i] = COPYRIGHT[i];
        i += 1;
    }
    text
};

/// The counts of the codes of each length, aligned for the vector stores
#[repr(align(16))]
struct Counts([u16; MAX_BITS + 1]);

/// Row n holds a one in byte n, so adding the rows of every code length counts the lengths in
/// the 16 bytes of a vector.
#[cfg(any(target_feature = "neon", target_feature = "sse2"))]
#[repr(align(16))]
struct Ones([u8; 256]);

#[cfg(any(target_feature = "neon", target_feature = "sse2"))]
static ONE: Ones = {
    let mut one = [0; 256];
    let mut len = 0;
    while len < 16 {
        one[16 * len + len] = 1;
        len += 1;
    }
    Ones(one)
};

/* Count number of codes for each code length. */
/// # Safety
///
/// `lens` must be valid for reads of `codes` lengths, which are all at most MAX_BITS.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[inline]
unsafe fn count_lengths(lens: *const u16, codes: usize, count: &mut Counts) {
    use core::arch::aarch64::{
        vaddl_u8, vaddq_u8, vdupq_n_u8, vget_high_u8, vget_low_u8, vld1q_u8, vst1q_u16,
    };

    // SAFETY: the caller guarantees the lengths, so every row lies inside the table. Each
    // vector takes at most 144 additions of a one, which a byte holds.
    unsafe {
        let one = ONE.0.as_ptr();
        let mut s1 = vdupq_n_u8(0);
        let mut s2 = vdupq_n_u8(0);

        if codes & 1 != 0 {
            s1 = vld1q_u8(one.add(16 * *lens as usize));
        }
        let mut sym = codes & 1;
        while sym < codes {
            s1 = vaddq_u8(s1, vld1q_u8(one.add(16 * *lens.add(sym) as usize)));
            s2 = vaddq_u8(s2, vld1q_u8(one.add(16 * *lens.add(sym + 1) as usize)));
            sym += 2;
        }

        let count = count.0.as_mut_ptr();
        vst1q_u16(count, vaddl_u8(vget_low_u8(s1), vget_low_u8(s2)));
        vst1q_u16(count.add(8), vaddl_u8(vget_high_u8(s1), vget_high_u8(s2)));
    }
}

/// # Safety
///
/// `lens` must be valid for reads of `codes` lengths, which are all at most MAX_BITS.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse2"
))]
#[inline]
unsafe fn count_lengths(lens: *const u16, codes: usize, count: &mut Counts) {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    // SAFETY: the caller guarantees the lengths, so every row lies inside the table, which is
    // aligned for the loads. Each vector takes at most 144 additions of a one, which a byte holds.
    unsafe {
        let one = ONE.0.as_ptr();
        let mut s1 = _mm_setzero_si128();
        let mut s2 = _mm_setzero_si128();

        if codes & 1 != 0 {
            s1 = _mm_load_si128(one.add(16 * *lens as usize).cast::<__m128i>());
        }
        let mut sym = codes & 1;
        while sym < codes {
            let row1 = one.add(16 * *lens.add(sym) as usize).cast::<__m128i>();
            let row2 = one.add(16 * *lens.add(sym + 1) as usize).cast::<__m128i>();
            s1 = _mm_add_epi8(s1, _mm_load_si128(row1));
            s2 = _mm_add_epi8(s2, _mm_load_si128(row2));
            sym += 2;
        }

        let count = count.0.as_mut_ptr();
        #[cfg(target_feature = "avx2")]
        {
            let w1 = _mm256_cvtepu8_epi16(s1);
            let w2 = _mm256_cvtepu8_epi16(s2);
            let sum = _mm256_add_epi16(w1, w2);

            _mm256_storeu_si256(count.cast::<__m256i>(), sum);
        }
        #[cfg(not(target_feature = "avx2"))]
        {
            let zero = _mm_setzero_si128();

            let s1_lo = _mm_unpacklo_epi8(s1, zero);
            let s2_lo = _mm_unpacklo_epi8(s2, zero);
            let sum_lo = _mm_add_epi16(s1_lo, s2_lo);
            _mm_storeu_si128(count.cast::<__m128i>(), sum_lo);

            let s1_hi = _mm_unpackhi_epi8(s1, zero);
            let s2_hi = _mm_unpackhi_epi8(s2, zero);
            let sum_hi = _mm_add_epi16(s1_hi, s2_hi);
            _mm_storeu_si128(count.add(8).cast::<__m128i>(), sum_hi);
        }
    }
}

// The AltiVec intrinsics are not stable in Rust, so PowerPC counts the lengths one by one too.
/// # Safety
///
/// `lens` must be valid for reads of `codes` lengths, which are all at most MAX_BITS.
#[cfg(not(any(
    all(target_arch = "aarch64", target_feature = "neon"),
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2"
    )
)))]
#[inline]
unsafe fn count_lengths(lens: *const u16, codes: usize, count: &mut Counts) {
    count.0 = [0; MAX_BITS + 1];
    for sym in 0..codes {
        // SAFETY: the caller guarantees the lengths, which are at most MAX_BITS.
        unsafe { *count.0.get_unchecked_mut(*lens.add(sym) as usize) += 1 };
    }
}

/// Length codes 257..285 base
static LBASE: [u16; 31] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0, 0,
];
/// Length codes 257..285 extra
static LEXT: [u16; 31] = [
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20,
    21, 21, 21, 21, 16, 199, 75,
];
/// Distance codes 0..29 base
static DBASE: [u16; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0,
];
/// Distance codes 0..29 extra
static DEXT: [u16; 32] = [
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22, 23, 23, 24, 24, 25, 25, 26, 26,
    27, 27, 28, 28, 29, 29, 64, 64,
];

/* The packed table fill below reads and writes each entry as a single uint32_t. */
const _: () = assert!(size_of::<code>() == 4, "code entry must be exactly 4 bytes");

/*
  Build a set of tables to decode the provided canonical Huffman code.
  The code lengths are lens[0..codes-1].  The result starts at *table,
  whose indices are 0..2^bits-1.  work is a writable array of at least
  lens shorts, which is used as a work area.  type is the type of code
  to be generated, CODES, LENS, or DISTS.  On return, zero is success,
  -1 is an invalid code, and +1 means that ENOUGH isn't enough.  table
  on return points to the next available entry's address.  bits is the
  requested root table index bits, and on return it is the actual root
  table index bits.  It will differ if the request is greater than the
  longest code or if it is less than the shortest code.
*/
/// # Safety
///
/// `lens` must hold `codes` lengths that are all at most MAX_BITS, and `work` must be writable
/// for as many values. `table` must point to space for the tables, which is ENOUGH_LENS entries
/// for LENS, ENOUGH_DISTS for DISTS and two to the power of `bits` for CODES. `bits` must be
/// valid for reads and writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_inflate_table(
    r#type: codetype,
    lens: *mut u16,
    codes: c_uint,
    table: *mut *mut code,
    bits: *mut c_uint,
    work: *mut u16,
) -> i32 {
    let mut len: u32; /* a code's length in bits */
    let mut sym: u32; /* index of code symbols */
    let mut min: u32; /* minimum code length */
    let mut max: u32; /* maximum code length */
    let mut root: u32; /* number of index bits for root table */
    let mut curr: u32; /* number of index bits for current table */
    let mut drop: u32; /* code bits to drop for sub-table */
    let mut left: i32; /* number of prefix codes available */
    let mut used: u32; /* code entries in table used */
    let mut rhuff: u16; /* Reversed huffman code */
    let mut huff: u32; /* Huffman code */
    let mut incr: u32; /* for incrementing code, index */
    let mut fill: u32; /* index for replicating entries */
    let mut low: u32; /* low bits for current root entry */
    let mut here: code; /* table entry for duplication */
    let mut next: *mut code; /* next available space in table */
    let base: *const u16; /* base value table to use */
    let extra: *const u16; /* extra bits table to use */
    let r#match: u32; /* use base and extra for symbol >= match */
    let mut count = Counts([0; MAX_BITS + 1]); /* number of codes of each length */
    let mut offs = [0u16; MAX_BITS + 1]; /* offsets in table for each length */

    /*
      Process a set of code lengths to create a canonical Huffman code.  The
      code lengths are lens[0..codes-1].  Each length corresponds to the
      symbols 0..codes-1.  The Huffman code is generated by first sorting the
      symbols by length from short to long, and retaining the symbol order
      for codes with equal lengths.  Then the code starts with all zero bits
      for the first code of the shortest length, and the codes are integer
      increments for the same length, and zeros are appended as the length
      increases.  For the deflate format, these bits are stored backwards
      from their more natural integer increment ordering, and so when the
      decoding tables are built in the large loop below, the integer codes
      are incremented backwards.

      This routine assumes, but does not check, that all of the entries in
      lens[] are in the range 0..MAXBITS.  The caller must assure this.
      1..MAXBITS is interpreted as that code length.  zero means that that
      symbol does not occur in this code.

      The codes are sorted by computing a count of codes for each length,
      creating from that a table of starting indices for each length in the
      sorted table, and then entering the symbols in order in the sorted
      table.  The sorted table is work[], with that space being provided by
      the caller.

      The length counts are used for other purposes as well, i.e. finding
      the minimum and maximum length codes, determining if there are any
      codes at all, checking for a valid set of lengths, and looking ahead
      at length counts to determine sub-table sizes when building the
      decoding tables.
    */

    // SAFETY: the caller guarantees the lengths, the work area and the table space. Every length
    // is at most MAX_BITS, which keeps the indexes into count and offs in range, and the checks
    // against ENOUGH_LENS and ENOUGH_DISTS keep the entries inside the table space.
    unsafe {
        let table_start = *table;

        /* accumulate lengths for codes (assumes lens[] all in 0..MAXBITS) */
        count_lengths(lens, codes as usize, &mut count);
        let count = count.0.as_mut_ptr();

        /* bound code lengths, force root to be within code lengths */
        root = *bits;
        max = MAX_BITS as u32;
        while max >= 1 {
            if *count.add(max as usize) != 0 {
                break;
            }
            max -= 1;
        }
        root = root.min(max);
        if unlikely(max == 0) {
            /* no symbols to code at all */
            here = code {
                op: 64, /* invalid code marker */
                bits: 1,
                val: 0,
            };
            /* make a table to force an error */
            *table_start = here;
            *table_start.add(1) = here;
            *table = table_start.add(2);
            *bits = 1;
            return 0; /* no symbols, but wait for decoding to report error */
        }
        min = 1;
        while min < max {
            if *count.add(min as usize) != 0 {
                break;
            }
            min += 1;
        }
        root = root.max(min);

        /* check for an over-subscribed or incomplete set of lengths */
        left = 1;
        for len in 1..MAX_BITS + 1 {
            left <<= 1;
            left -= i32::from(*count.add(len));
            if left < 0 {
                return -1; /* over-subscribed */
            }
        }
        if left > 0 && (r#type == CODES || max != 1) {
            return -1; /* incomplete set */
        }

        /* generate offsets into symbol table for each length for sorting */
        offs[1] = 0;
        for len in 1..MAX_BITS {
            offs[len + 1] = offs[len].wrapping_add(*count.add(len));
        }

        /* sort symbols by length, by symbol order within each length */
        let offs = offs.as_mut_ptr();
        for sym in 0..codes {
            let len = *lens.add(sym as usize);
            if len != 0 {
                let off = offs.add(len as usize);
                *work.add(*off as usize) = sym as u16;
                *off = (*off).wrapping_add(1);
            }
        }

        /*
          Create and fill in decoding tables.  In this loop, the table being
          filled is at next and has curr index bits.  The code being used is huff
          with length len.  That code is converted to an index by dropping drop
          bits off of the bottom.  For codes where len is less than drop + curr,
          those top drop + curr - len bits are incremented through all values to
          fill the table with replicated entries.

          root is the number of index bits for the root table.  When len exceeds
          root, sub-tables are created pointed to by the root entry with an index
          of the low root bits of huff.  This is saved in low to check for when a
          new sub-table should be started.  drop is zero when the root table is
          being filled, and drop is root when sub-tables are being filled.

          When a new sub-table is needed, it is necessary to look ahead in the
          code lengths to determine what size sub-table is needed.  The length
          counts are used for this, and so count[] is decremented as codes are
          entered in the tables.

          used keeps track of how many table entries have been allocated from the
          provided *table space.  It is checked for LENS and DIST tables against
          the constants ENOUGH_LENS and ENOUGH_DISTS to guard against changes in
          the initial root table size constants.  See the comments in inftrees.h
          for more information.

          sym increments through all symbols, and the loop terminates when
          all codes of length max, i.e. all codes, have been processed.  This
          routine permits incomplete codes, so another loop after this one fills
          in the rest of the decoding tables with invalid code markers.
        */

        /* set up for code type */
        match r#type {
            CODES => {
                /* dummy value--not used */
                base = work;
                extra = work;
                r#match = 20;
            }
            LENS => {
                base = LBASE.as_ptr();
                extra = LEXT.as_ptr();
                r#match = 257;
            }
            _ => {
                base = DBASE.as_ptr();
                extra = DEXT.as_ptr();
                r#match = 0;
            }
        }

        /* initialize state for loop */
        rhuff = 0; /* starting code, reversed */
        huff = 0; /* starting code */
        sym = 0; /* starting code symbol */
        len = min; /* starting code length */
        next = table_start; /* current table to fill in */
        curr = root; /* current table index bits */
        drop = 0; /* current bits to drop from code for index */
        low = u32::MAX; /* trigger new sub-table when len > root */
        used = 1 << root; /* use root table entries */
        let mask = used - 1; /* mask for comparing low */

        /* check available table space */
        if (r#type == LENS && used > ENOUGH_LENS as u32)
            || (r#type == DISTS && used > ENOUGH_DISTS as u32)
        {
            return 1;
        }

        /* process all codes and make table entries */
        loop {
            /* create table entry */
            let code_bits = (len - drop) as u8;
            let symbol = u32::from(*work.add(sym as usize));
            if likely(symbol >= r#match) {
                let op = u32::from(*extra.add((symbol - r#match) as usize));
                here = code {
                    op: combine_op(op, code_bits),
                    bits: combine_bits(code_bits, op),
                    val: *base.add((symbol - r#match) as usize),
                };
            } else if symbol + 1 < r#match {
                here = code {
                    op: 0,
                    bits: code_bits,
                    val: symbol as u16,
                };
            } else {
                here = code {
                    op: 32 + 64, /* end of block */
                    bits: code_bits,
                    val: 0,
                };
            }

            /* replicate for those indices with low len bits equal to huff */
            incr = 1 << (len - drop);
            fill = 1 << curr;
            min = fill; /* save offset to next table */
            {
                /* `here` is a 4-byte struct that the compiler writes one field at a time.
                Read it as a packed uint32_t so each slot is filled by a single store. */
                let here_u32 = core::mem::transmute::<code, u32>(here);
                let base_ptr = next.add((huff >> drop) as usize);
                let step4 = incr << 2;
                /* Unroll by four so the slot addresses are independent. */
                while fill >= step4 {
                    zng_memwrite_4(base_ptr.add((fill - incr) as usize).cast::<u8>(), here_u32);
                    zng_memwrite_4(
                        base_ptr.add((fill - 2 * incr) as usize).cast::<u8>(),
                        here_u32,
                    );
                    zng_memwrite_4(
                        base_ptr.add((fill - 3 * incr) as usize).cast::<u8>(),
                        here_u32,
                    );
                    zng_memwrite_4(
                        base_ptr.add((fill - 4 * incr) as usize).cast::<u8>(),
                        here_u32,
                    );
                    fill -= step4;
                }
                while fill != 0 {
                    fill -= incr;
                    zng_memwrite_4(base_ptr.add(fill as usize).cast::<u8>(), here_u32);
                }
            }

            /* backwards increment the len-bit code huff */
            rhuff = rhuff.wrapping_add((0x8000u32 >> (len - 1)) as u16);
            huff = u32::from(rhuff.reverse_bits());

            /* go to next symbol, update count, len */
            sym += 1;
            let remaining = count.add(len as usize);
            *remaining = (*remaining).wrapping_sub(1);
            if *remaining == 0 {
                if len == max {
                    break;
                }
                len = u32::from(*lens.add(*work.add(sym as usize) as usize));
            }

            /* create new sub-table if needed */
            if len > root && (huff & mask) != low {
                /* if first time, transition to sub-tables */
                if drop == 0 {
                    drop = root;
                }

                /* increment past last table */
                next = next.add(min as usize); /* here min is 1 << curr */

                /* determine length of next table */
                curr = len - drop;
                left = 1 << curr;
                while curr + drop < max {
                    left -= i32::from(*count.add((curr + drop) as usize));
                    if left <= 0 {
                        break;
                    }
                    curr += 1;
                    left <<= 1;
                }

                /* check for enough space */
                used += 1 << curr;
                if (r#type == LENS && used > ENOUGH_LENS as u32)
                    || (r#type == DISTS && used > ENOUGH_DISTS as u32)
                {
                    return 1;
                }

                /* point entry in root table to sub-table */
                low = huff & mask;
                *table_start.add(low as usize) = code {
                    op: curr as u8,
                    bits: root as u8,
                    val: next.offset_from(table_start) as u16,
                };
            }
        }

        /* fill in remaining table entry if code is incomplete (guaranteed to have
        at most one remaining entry, since if the code is incomplete, the
        maximum code length that was allowed to get this far is one bit) */
        if unlikely(huff != 0) {
            *next.add(huff as usize) = code {
                op: 64, /* invalid code marker */
                bits: (len - drop) as u8,
                val: 0,
            };
        }

        /* set return parameters */
        *table = table_start.add(used as usize);
        *bits = root;
    }
    0
}
