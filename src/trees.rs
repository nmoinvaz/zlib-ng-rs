//! trees.c -- output deflated data using Huffman coding
//! Copyright (C) 1995-2026 Jean-loup Gailly
//! detect_data_type() function provided freely by Cosmin Truta, 2006
//! For conditions of distribution and use, see copyright notice in zlib.h

/*
 *  ALGORITHM
 *
 *      The "deflation" process uses several Huffman trees. The more
 *      common source values are represented by shorter bit sequences.
 *
 *      Each code tree is stored in a compressed form which is itself
 * a Huffman encoding of the lengths of all the code strings (in
 * ascending order by source values).  The actual code strings are
 * reconstructed from the lengths in the inflate process, as described
 * in the deflate specification.
 *
 *  REFERENCES
 *
 *      Deutsch, L.P.,"'Deflate' Compressed Data Format Specification".
 *      Available in ftp.uu.net:/pub/archiving/zip/doc/deflate-1.1.doc
 *
 *      Storer, James A.
 *          Data Compression:  Methods and Theory, pp. 49-50.
 *          Computer Science Press, 1988.  ISBN 0-7167-8156-5.
 *
 *      Sedgewick, R.
 *          Algorithms, p290.
 *          Addison-Wesley, 1983. ISBN 0-201-06672-6.
 */

use core::ffi::{c_int, c_uint};
use core::ptr;

use crate::deflate::{
    BL_CODES, D_CODES, END_BLOCK, L_CODES, LENGTH_CODES, LITERALS, cmpr_bits_add, cmpr_bits_align,
    ct_data, debug_bits_match, debug_bits_reset, deflate_state, put_byte, put_short, put_uint32,
    sent_bits_add, tree_desc,
};
use crate::deflate_p::bi_reverse;
use crate::trees_emit::{
    send_bits, send_bits_flush, send_bits_merge, send_code, send_code_merge, zng_assemble_dist,
    zng_emit_end_block, zng_tr_emit_align, zng_tr_emit_end_block, zng_tr_emit_tree,
};
pub(crate) use crate::trees_tbl::{
    dmask_extra, lmask_extra, static_dtree, static_ltree, zng_dist_code, zng_length_code,
};
#[cfg(not(feature = "lit-mem"))]
use crate::zbuild::OPTIMAL_CMP;
use crate::zbuild::unlikely;
use crate::zlib::{Z_BINARY, Z_FIXED, Z_TEXT, Z_UNKNOWN};
#[cfg(not(feature = "lit-mem"))]
use crate::zmemory::{zng_memread_4, zng_memread_8};
use crate::zutil::{DYN_TREES, MAX_BITS, STATIC_TREES, STORED_BLOCK};

/* Constants */

/// see definition of array dist_code in trees.c
pub(crate) const DIST_CODE_LEN: usize = 512;

/// Bit length codes must not exceed MAX_BL_BITS bits
const MAX_BL_BITS: usize = 7;

/// repeat previous bit length 3-6 times (2 bits of repeat count)
const REP_3_6: usize = 16;

/// repeat a zero length 3-10 times  (3 bits of repeat count)
const REPZ_3_10: usize = 17;

/// repeat a zero length 11-138 times  (7 bits of repeat count)
const REPZ_11_138: usize = 18;

/// extra bits for each length code
static EXTRA_LBITS: [c_int; LENGTH_CODES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// extra bits for each distance code
static EXTRA_DBITS: [c_int; D_CODES] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// extra bits for each bit length code
static EXTRA_BLBITS: [c_int; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];

/// The lengths of the bit length codes are sent in order of decreasing
/// probability, to avoid transmitting the lengths for unused bit length codes.
static BL_ORDER: [u8; BL_CODES] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/* ===========================================================================
 * Local data. These are initialized only once.
 */

#[allow(non_camel_case_types)]
#[repr(C)]
pub(crate) struct static_tree_desc {
    /// static tree or NULL
    static_tree: *const ct_data,
    /// extra bits for each code or NULL
    extra_bits: *const c_int,
    /// base index for extra_bits
    extra_base: c_int,
    /// max number of elements in the tree
    elems: c_int,
    /// max bit length for the codes
    max_length: c_uint,
}

// SAFETY: the descriptors are never written, and they only point at tables that are never written.
unsafe impl Sync for static_tree_desc {}

static STATIC_L_DESC: static_tree_desc = static_tree_desc {
    static_tree: static_ltree.as_ptr(),
    extra_bits: EXTRA_LBITS.as_ptr(),
    extra_base: (LITERALS + 1) as c_int,
    elems: L_CODES as c_int,
    max_length: MAX_BITS as c_uint,
};

static STATIC_D_DESC: static_tree_desc = static_tree_desc {
    static_tree: static_dtree.as_ptr(),
    extra_bits: EXTRA_DBITS.as_ptr(),
    extra_base: 0,
    elems: D_CODES as c_int,
    max_length: MAX_BITS as c_uint,
};

static STATIC_BL_DESC: static_tree_desc = static_tree_desc {
    static_tree: ptr::null(),
    extra_bits: EXTRA_BLBITS.as_ptr(),
    extra_base: 0,
    elems: BL_CODES as c_int,
    max_length: MAX_BL_BITS as c_uint,
};

/// Mapping from a distance to a distance code. dist is the distance - 1 and must be lower than
/// 32768.
///
/// # Safety
///
/// `dist` must be below 32768.
#[inline(always)]
pub(crate) unsafe fn d_code(dist: u32) -> u8 {
    if dist < 256 {
        zng_dist_code[dist as usize]
    } else {
        // SAFETY: the caller guarantees dist is below 32768, so the index is below DIST_CODE_LEN.
        unsafe { *zng_dist_code.get_unchecked(256 + (dist >> 7) as usize) }
    }
}

/* ===========================================================================
 * Initialize the tree data structures for a new zlib stream.
 */
/// # Safety
///
/// `s` must point to a deflate_state.
// Kept out of line, as it is across the C source files.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_tr_init(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the state is valid.
    unsafe {
        (*s).l_desc.dyn_tree = (&raw mut (*s).dyn_ltree).cast::<ct_data>();
        (*s).l_desc.stat_desc = &raw const STATIC_L_DESC;

        (*s).d_desc.dyn_tree = (&raw mut (*s).dyn_dtree).cast::<ct_data>();
        (*s).d_desc.stat_desc = &raw const STATIC_D_DESC;

        (*s).bl_desc.dyn_tree = (&raw mut (*s).bl_tree).cast::<ct_data>();
        (*s).bl_desc.stat_desc = &raw const STATIC_BL_DESC;

        (*s).bi_buf = 0;
        (*s).bi_valid = 0;
        (*s).bi_used = 0;
        debug_bits_reset(s);

        /* Initialize the first block of the first file: */
        init_block(s);
    }
}

/* ===========================================================================
 * Initialize a new block.
 */
/// # Safety
///
/// `s` must point to a deflate_state.
unsafe fn init_block(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the state is valid, and nothing else refers to its trees.
    unsafe {
        let dyn_ltree = (&raw mut (*s).dyn_ltree).cast::<ct_data>();
        let dyn_dtree = (&raw mut (*s).dyn_dtree).cast::<ct_data>();
        let bl_tree = (&raw mut (*s).bl_tree).cast::<ct_data>();

        /* Initialize the trees. */
        for n in 0..L_CODES {
            (*dyn_ltree.add(n)).fc = 0;
        }
        for n in 0..D_CODES {
            (*dyn_dtree.add(n)).fc = 0;
        }
        for n in 0..BL_CODES {
            (*bl_tree.add(n)).fc = 0;
        }

        (*dyn_ltree.add(END_BLOCK)).fc = 1;
        (*s).static_len = 0;
        (*s).opt_len = 0;
        (*s).sym_next = 0;
    }
}

/* Queue entries pack freq above the node index, so a single 32-bit compare orders nodes by
 * frequency, breaking ties by node index: leaves first, then internal nodes in creation order,
 * which keeps the worst-case code length small. */
const PQ_NODE_BITS: u32 = 10;

#[inline(always)]
const fn pq_pack(freq: u32, node: usize) -> u32 {
    (freq << PQ_NODE_BITS) | node as u32
}

#[inline(always)]
const fn pq_node(e: u32) -> usize {
    (e & ((1 << PQ_NODE_BITS) - 1)) as usize
}

#[inline(always)]
const fn pq_freq(e: u32) -> u32 {
    e >> PQ_NODE_BITS
}

/* ===========================================================================
 * One stable counting-sort pass over an 8-bit digit of the packed entries.
 * count holds the digit histogram at offset +1, accumulated during the leaf
 * scan, and is turned into running start positions here. Used by build_tree().
 */
/// # Safety
///
/// `src` must hold `n` entries that `count` counted, and `dst` must have room for them.
unsafe fn pq_radix_pass(
    src: *const u32,
    dst: *mut u32,
    n: usize,
    shift: u32,
    count: &mut [u16; 257],
) {
    for i in 1..=256 {
        count[i] = count[i].wrapping_add(count[i - 1]);
    }
    for i in 0..n {
        // SAFETY: the caller guarantees src holds n entries, and the histogram keeps every start
        // position below n.
        unsafe {
            let e = *src.add(i);
            let start = &mut count[((e >> shift) & 0xFF) as usize];
            *dst.add(usize::from(*start)) = e;
            *start += 1;
        }
    }
}

/* ===========================================================================
 * Take the smaller of the two queue heads: the next unused leaf, or the next
 * created internal node. Used by build_tree().
 */
/// # Safety
///
/// `leaves` must hold `nleaves` entries and `internals` must hold `itail` entries, and one of the
/// two queues must not be empty.
#[inline(always)]
unsafe fn pq_take(
    leaves: *const u32,
    li: &mut usize,
    nleaves: usize,
    internals: *const u32,
    ihead: &mut usize,
    itail: usize,
) -> u32 {
    // SAFETY: the caller guarantees both queues hold the entries that the positions refer to.
    unsafe {
        if *li < nleaves && (*ihead == itail || *leaves.add(*li) < *internals.add(*ihead)) {
            let e = *leaves.add(*li);
            *li += 1;
            return e;
        }
        let e = *internals.add(*ihead);
        *ihead += 1;
        e
    }
}

/* ===========================================================================
 * Construct one Huffman tree and assigns the code bit strings and lengths.
 * Update the total bit length for the current block.
 * IN assertion: the field freq is set for all tree elements.
 * OUT assertions: the fields len and code are set to the optimal bit length
 *     and corresponding code. The length opt_len is updated; static_len is
 *     also updated if stree is not null. The field max_code is set.
 */
/// # Safety
///
/// `s` must point to a deflate_state and `desc` to one of its tree descriptors.
unsafe fn build_tree(s: *mut deflate_state, desc: *mut tree_desc) {
    /* desc: the tree descriptor */
    // SAFETY: the caller guarantees the state and the descriptor are valid. A tree holds
    // 2 * elems + 1 nodes, and the two queue buffers hold L_CODES + 1 entries each.
    unsafe {
        let tree = (*desc).dyn_tree;
        let stree = (*(*desc).stat_desc).static_tree;
        let elems = (*(*desc).stat_desc).elems as usize;
        let mut max_code: c_int = -1; /* largest code with non zero frequency */
        let mut nleaves = 0;
        /* queue positions for leaves and internal nodes */
        let mut li = 0;
        let mut ihead = 0;
        let mut itail = 0;
        /* packed leaf entries, sorted by frequency */
        let leaves = (&raw mut (*s).pq_leaves).cast::<u32>();
        /* radix buffer, then FIFO of created internal nodes */
        let scratch = (&raw mut (*s).pq_scratch).cast::<u32>();
        let mut sorted = leaves; /* sorted leaves, in scratch after a single pass */
        let mut internals = scratch; /* internal node FIFO, in whichever buffer is free */
        let mut count_lo = [0u16; 257]; /* histogram of the low frequency byte, at offset +1 */
        let mut count_hi = [0u16; 257]; /* histogram of the high frequency byte, at offset +1 */

        for n in 0..elems {
            let freq = (*tree.add(n)).fc;
            if freq != 0 {
                *leaves.add(nleaves) = pq_pack(u32::from(freq), n);
                nleaves += 1;
                count_lo[usize::from(freq & 0xFF) + 1] += 1;
                count_hi[usize::from(freq >> 8) + 1] += 1;
                max_code = n as c_int;
            } else {
                (*tree.add(n)).dl = 0;
            }
        }

        /* The pkzip format requires that at least one distance code exists,
         * and that at least one bit should be sent even if there is only one
         * possible code. So to avoid special checks later on we force at least
         * two codes of non zero frequency.
         */
        while nleaves < 2 {
            let node = if max_code < 2 {
                max_code += 1;
                max_code as usize
            } else {
                0
            };
            *leaves.add(nleaves) = pq_pack(1, node);
            nleaves += 1;
            (*tree.add(node)).fc = 1;
            // The lengths go below zero here and come back when gen_bitlen adds this node.
            (*s).opt_len = (*s).opt_len.wrapping_sub(1);
            if !stree.is_null() {
                (*s).static_len = (*s)
                    .static_len
                    .wrapping_sub(u32::from((*stree.add(node)).dl));
            }
            /* node is 0 or 1 so it does not have extra bits */
        }
        (*desc).max_code = max_code;

        /* Sort the leaves by packed entry. The scan above appended them in node order, which is
         * ascending in the node bits, so two stable passes over the freq bytes finish the sort.
         * A forced node can arrive out of node order, but then there are exactly two leaves,
         * so the radix path only ever sorts entries the histograms counted. */
        if nleaves == 2 {
            if *leaves > *leaves.add(1) {
                ptr::swap(leaves, leaves.add(1));
            }
        } else if usize::from(count_hi[1]) == nleaves {
            /* Every frequency fits in one byte, so the first pass already produces the final
             * order. The sorted entries then live in scratch, so the internal-node FIFO takes
             * over the leaves buffer instead. */
            pq_radix_pass(leaves, scratch, nleaves, PQ_NODE_BITS, &mut count_lo);
            sorted = scratch;
            internals = leaves;
        } else {
            /* Sort by the low then high frequency byte, ending back in leaves. */
            pq_radix_pass(leaves, scratch, nleaves, PQ_NODE_BITS, &mut count_lo);
            pq_radix_pass(scratch, leaves, nleaves, PQ_NODE_BITS + 8, &mut count_hi);
        }

        /* Construct the Huffman tree by repeatedly combining the least two frequent nodes.
         * Sorted leaves and the FIFO of created nodes are each ascending, because merge sums
         * never decrease, so the two smallest nodes are always at the queue heads.
         */
        let mut node = elems; /* next internal node of the tree */
        for _ in 1..nleaves {
            /* en = entry of least frequency, em = entry of next least frequency */
            let en = pq_take(sorted, &mut li, nleaves, internals, &mut ihead, itail);
            let em = pq_take(sorted, &mut li, nleaves, internals, &mut ihead, itail);
            let n = pq_node(en);
            let m = pq_node(em);

            /* Create a new node father of n and m. Freq wraps the same way the uint16_t
             * state field did. */
            let f = (pq_freq(en) + pq_freq(em)) as u16;
            (*tree.add(node)).fc = f;
            (*tree.add(n)).dl = node as u16;
            (*tree.add(m)).dl = node as u16;
            /* and append the new node to the internal queue */
            *internals.add(itail) = pq_pack(u32::from(f), node);
            itail += 1;
            node += 1;
        }

        /* At this point, the fields freq and dad are set. We can now
         * generate the bit lengths.
         */
        gen_bitlen(s, desc, sorted, nleaves, node - 1);

        /* The field len is now set, we can generate the bit codes */
        gen_codes(tree, max_code, (&raw mut (*s).bl_count).cast::<u16>());
    }
}

/* ===========================================================================
 * Compute the optimal bit lengths for a tree and update the total bit length
 * for the current block.
 * IN assertion: the fields freq and dad are set, sorted holds the leaves by
 *    increasing frequency, and root is the last created node.
 * OUT assertions: the field len is set to the optimal bit length, the
 *     array bl_count contains the frequencies for each bit length.
 *     The length opt_len is updated; static_len is also updated if stree is
 *     not null. Used by build_tree().
 */
/// # Safety
///
/// `s` must point to a deflate_state and `desc` to one of its tree descriptors, and the IN
/// assertion must hold.
unsafe fn gen_bitlen(
    s: *mut deflate_state,
    desc: *mut tree_desc,
    sorted: *const u32,
    nleaves: usize,
    root: usize,
) {
    /* desc: the tree descriptor */
    // SAFETY: the caller guarantees the state, the descriptor and the IN assertion. Every dad is
    // a node of the tree, and every bit length is at most max_length, which is at most MAX_BITS.
    unsafe {
        let tree = (*desc).dyn_tree;
        let elems = (*(*desc).stat_desc).elems as usize;
        let stree = (*(*desc).stat_desc).static_tree;
        let extra = (*(*desc).stat_desc).extra_bits;
        let base = (*(*desc).stat_desc).extra_base as usize;
        let max_length = (*(*desc).stat_desc).max_length;
        let bl_count = (&raw mut (*s).bl_count).cast::<u16>();
        let mut overflow: c_int = 0; /* number of elements with bit length too large */

        // Rust cannot tell that the stores into the tree and into bl_count leave the state alone,
        // so the two block lengths are kept in locals and written back once.
        let mut opt_len = (*s).opt_len;
        let mut static_len = (*s).static_len;

        ptr::write_bytes(bl_count, 0, MAX_BITS + 1);

        /* In a first pass, compute the optimal bit lengths (which may
         * overflow in the case of the bit length tree).
         */
        (*tree.add(root)).dl = 0; /* root of the tree */

        /* Dads are created after their sons, so a descending walk visits each dad first */
        for n in (elems..root).rev() {
            let mut bits = c_uint::from((*tree.add(usize::from((*tree.add(n)).dl))).dl) + 1;
            if bits > max_length {
                bits = max_length;
                overflow += 1;
            }
            (*tree.add(n)).dl = bits as u16;
            /* We overwrite tree[n].Dad which is no longer needed */
        }

        for i in 0..nleaves {
            let n = pq_node(*sorted.add(i));
            let mut bits = c_uint::from((*tree.add(usize::from((*tree.add(n)).dl))).dl) + 1;
            if bits > max_length {
                bits = max_length;
                overflow += 1;
            }
            (*tree.add(n)).dl = bits as u16;

            *bl_count.add(bits as usize) += 1;
            let mut xbits = 0;
            if n >= base {
                xbits = *extra.add(n - base) as c_uint;
            }
            let f = c_uint::from((*tree.add(n)).fc);
            opt_len = opt_len.wrapping_add(f * (bits + xbits));
            if !stree.is_null() {
                static_len =
                    static_len.wrapping_add(f * (c_uint::from((*stree.add(n)).dl) + xbits));
            }
        }
        (*s).static_len = static_len;
        if overflow == 0 {
            (*s).opt_len = opt_len;
            return;
        }

        /* This happens for example on obj2 and pic of the Calgary corpus */

        /* Find the first bit length which could increase: */
        loop {
            let mut bits = max_length as usize - 1;
            while *bl_count.add(bits) == 0 {
                bits -= 1;
            }
            *bl_count.add(bits) -= 1; /* move one leaf down the tree */
            *bl_count.add(bits + 1) += 2; /* move one overflow item as its brother */
            *bl_count.add(max_length as usize) -= 1;
            /* The brother of the overflow item also moves one step up,
             * but this does not affect bl_count[max_length]
             */
            overflow -= 2;
            if overflow <= 0 {
                break;
            }
        }

        /* Now recompute all bit lengths, scanning in increasing frequency.
         * (It is simpler to reconstruct all lengths instead of fixing only
         * the wrong ones. This idea is taken from 'ar' written by Haruhiko Okumura.)
         */
        let mut i = 0;
        for bits in (1..=max_length).rev() {
            let mut n = *bl_count.add(bits as usize);
            while n != 0 {
                let m = pq_node(*sorted.add(i));
                i += 1;
                let len = c_uint::from((*tree.add(m)).dl);
                if len != bits {
                    let freq = c_uint::from((*tree.add(m)).fc);
                    opt_len = opt_len.wrapping_add(bits * freq);
                    opt_len = opt_len.wrapping_sub(len * freq);
                    (*tree.add(m)).dl = bits as u16;
                }
                n -= 1;
            }
        }
        (*s).opt_len = opt_len;
    }
}

/* ===========================================================================
 * Generate the codes for a given tree and bit counts (which need not be
 * optimal).
 * IN assertion: the array bl_count contains the bit length statistics for
 * the given tree and the field len is set for all tree elements.
 * OUT assertion: the field code is set for all tree elements of non
 *     zero code length. Used by build_tree().
 */
/// # Safety
///
/// `tree` must hold more than `max_code` nodes and `bl_count` MAX_BITS + 1 counts, and the IN
/// assertion must hold.
pub(crate) unsafe fn gen_codes(tree: *mut ct_data, max_code: c_int, bl_count: *mut u16) {
    /* tree: the tree to decorate */
    /* max_code: largest code with non zero frequency */
    /* bl_count: number of codes at each bit length */
    let mut next_code = [0u16; MAX_BITS + 1]; /* next code value for each bit length */
    let mut code: u16 = 0; /* running code value */

    // SAFETY: the caller guarantees the tree and the counts are valid. Every code length is at
    // most MAX_BITS.
    unsafe {
        /* The distribution counts are first used to generate the code values
         * without bit reversal.
         */
        for (bits, next) in next_code.iter_mut().enumerate().skip(1) {
            code = code.wrapping_add(*bl_count.add(bits - 1)) << 1;
            *next = code;
        }
        /* Check that the bit counts in bl_count are consistent. The last code
         * must be all ones.
         */
        debug_assert!(
            c_int::from(code) + c_int::from(*bl_count.add(MAX_BITS)) - 1 == (1 << MAX_BITS) - 1,
            "inconsistent bit counts"
        );

        for n in 0..usize::try_from(max_code + 1).unwrap_or(0) {
            let len = (*tree.add(n)).dl;
            if len == 0 {
                continue;
            }
            /* Now reverse the bits */
            let next = next_code.get_unchecked_mut(usize::from(len));
            (*tree.add(n)).fc = bi_reverse(*next, len);
            *next = next.wrapping_add(1);
        }
    }
}

/* ===========================================================================
 * Scan a literal or distance tree to determine the frequencies of the codes
 * in the bit length tree.
 */
/// # Safety
///
/// `s` must point to a deflate_state and `tree` to one of its trees, with room for a guard
/// after `max_code`.
unsafe fn scan_tree(s: *mut deflate_state, tree: *mut ct_data, max_code: c_int) {
    /* tree: the tree to be scanned */
    /* max_code: and its largest code of non zero frequency */
    // SAFETY: the caller guarantees the state and the tree are valid. Every code length of the
    // tree is at most MAX_BITS, which is inside bl_tree.
    unsafe {
        let bl_tree = (&raw mut (*s).bl_tree).cast::<ct_data>();
        let mut prevlen: c_int = -1; /* last emitted length */
        let mut nextlen = c_int::from((*tree).dl); /* length of next code */
        let mut count: u16 = 0; /* repeat count of the current code */
        let mut max_count: u16 = 7; /* max repeat count */
        let mut min_count: u16 = 4; /* min repeat count */

        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        }

        (*tree.add((max_code + 1) as usize)).dl = 0xffff; /* guard */

        // An exclusive range, an inclusive one carries an extra flag through the loop.
        for n in 0..(max_code + 1) as usize {
            let curlen = nextlen; /* length of current code */
            nextlen = c_int::from((*tree.add(n + 1)).dl);
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                let freq = &mut (*bl_tree.add(curlen as usize)).fc;
                *freq = freq.wrapping_add(count);
            } else if curlen != 0 {
                if curlen != prevlen {
                    (*bl_tree.add(curlen as usize)).fc += 1;
                }
                (*bl_tree.add(REP_3_6)).fc += 1;
            } else if count <= 10 {
                (*bl_tree.add(REPZ_3_10)).fc += 1;
            } else {
                (*bl_tree.add(REPZ_11_138)).fc += 1;
            }
            count = 0;
            prevlen = curlen;
            if nextlen == 0 {
                max_count = 138;
                min_count = 3;
            } else if curlen == nextlen {
                max_count = 6;
                min_count = 3;
            } else {
                max_count = 7;
                min_count = 4;
            }
        }
    }
}

/* ===========================================================================
 * Send a literal or distance tree in compressed form, using the codes in
 * bl_tree.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for the tree, and `tree` to
/// one of its trees after scan_tree has set the guard.
unsafe fn send_tree(s: *mut deflate_state, tree: *mut ct_data, max_code: c_int) {
    /* tree: the tree to be scanned */
    /* max_code and its largest code of non zero frequency */
    // SAFETY: the caller guarantees the state and the tree are valid and the pending buffer has
    // room. Every code length of the tree is at most MAX_BITS, which is inside bl_tree.
    unsafe {
        let bl_tree = (&raw const (*s).bl_tree).cast::<ct_data>();
        let mut prevlen: c_int = -1; /* last emitted length */
        let mut nextlen = c_int::from((*tree).dl); /* length of next code */
        let mut count: c_int = 0; /* repeat count of the current code */
        let mut max_count: c_int = 7; /* max repeat count */
        let mut min_count: c_int = 4; /* min repeat count */

        /* tree[max_code+1].Len = -1; */
        /* guard already set */
        if nextlen == 0 {
            max_count = 138;
            min_count = 3;
        }

        // Temp local variables
        let mut bi_valid = (*s).bi_valid as u32;
        let mut bi_buf = (*s).bi_buf;

        // An exclusive range, an inclusive one carries an extra flag through the loop.
        for n in 0..(max_code + 1) as usize {
            let curlen = nextlen; /* length of current code */
            nextlen = c_int::from((*tree.add(n + 1)).dl);
            count += 1;
            if count < max_count && curlen == nextlen {
                continue;
            } else if count < min_count {
                loop {
                    send_code(s, curlen as usize, bl_tree, &mut bi_buf, &mut bi_valid);
                    count -= 1;
                    if count == 0 {
                        break;
                    }
                }
            } else if curlen != 0 {
                if curlen != prevlen {
                    send_code(s, curlen as usize, bl_tree, &mut bi_buf, &mut bi_valid);
                    count -= 1;
                }
                debug_assert!((3..=6).contains(&count), " 3_6?");
                send_code(s, REP_3_6, bl_tree, &mut bi_buf, &mut bi_valid);
                send_bits(s, (count - 3) as u64, 2, &mut bi_buf, &mut bi_valid);
            } else if count <= 10 {
                send_code(s, REPZ_3_10, bl_tree, &mut bi_buf, &mut bi_valid);
                send_bits(s, (count - 3) as u64, 3, &mut bi_buf, &mut bi_valid);
            } else {
                send_code(s, REPZ_11_138, bl_tree, &mut bi_buf, &mut bi_valid);
                send_bits(s, (count - 11) as u64, 7, &mut bi_buf, &mut bi_valid);
            }
            count = 0;
            prevlen = curlen;
            if nextlen == 0 {
                max_count = 138;
                min_count = 3;
            } else if curlen == nextlen {
                max_count = 6;
                min_count = 3;
            } else {
                max_count = 7;
                min_count = 4;
            }
        }

        // Store back temp variables
        (*s).bi_buf = bi_buf;
        (*s).bi_valid = bi_valid as i32;
    }
}

/* ===========================================================================
 * Construct the Huffman tree for the bit lengths and return the index in
 * bl_order of the last bit length code to send.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose literal and distance trees are built.
unsafe fn build_bl_tree(s: *mut deflate_state) -> c_int {
    // SAFETY: the caller guarantees the state is valid and both trees are built.
    unsafe {
        /* Determine the bit length frequencies for literal and distance trees */
        scan_tree(
            s,
            (&raw mut (*s).dyn_ltree).cast::<ct_data>(),
            (*s).l_desc.max_code,
        );
        scan_tree(
            s,
            (&raw mut (*s).dyn_dtree).cast::<ct_data>(),
            (*s).d_desc.max_code,
        );

        /* Build the bit length tree: */
        build_tree(s, &raw mut (*s).bl_desc);
        /* opt_len now includes the length of the tree representations, except
         * the lengths of the bit lengths codes and the 5+5+4 bits for the counts.
         */

        /* Determine the number of bit length codes to send. The pkzip format
         * requires that at least 4 bit length codes be sent. (appnote.txt says
         * 3 but the actual value used is 4.)
         */
        let bl_tree = (&raw const (*s).bl_tree).cast::<ct_data>();
        let mut max_blindex = BL_CODES - 1; /* index of last bit length code of non zero freq */
        while max_blindex >= 3 {
            if (*bl_tree.add(usize::from(BL_ORDER[max_blindex]))).dl != 0 {
                break;
            }
            max_blindex -= 1;
        }
        /* Update opt_len to include the bit length tree and counts */
        (*s).opt_len = (*s)
            .opt_len
            .wrapping_add(3 * (max_blindex as c_uint + 1) + 5 + 5 + 4);

        max_blindex as c_int
    }
}

/* ===========================================================================
 * Send the header for a block using dynamic Huffman trees: the counts, the
 * lengths of the bit length codes, the literal tree and the distance tree.
 * IN assertion: lcodes >= 257, dcodes >= 1, blcodes >= 4.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose three trees are built and whose pending buffer has
/// room for them, and the IN assertion must hold.
unsafe fn send_all_trees(s: *mut deflate_state, lcodes: c_int, dcodes: c_int, blcodes: c_int) {
    debug_assert!(
        lcodes >= 257 && dcodes >= 1 && blcodes >= 4,
        "not enough codes"
    );
    debug_assert!(
        lcodes as usize <= L_CODES && dcodes as usize <= D_CODES && blcodes as usize <= BL_CODES,
        "too many codes"
    );

    // SAFETY: the caller guarantees the state is valid and the pending buffer has room.
    unsafe {
        // Temp local variables
        let mut bi_valid = (*s).bi_valid as u32;
        let mut bi_buf = (*s).bi_buf;

        send_bits(s, (lcodes - 257) as u64, 5, &mut bi_buf, &mut bi_valid); /* not +255 as stated in appnote.txt */
        send_bits(s, (dcodes - 1) as u64, 5, &mut bi_buf, &mut bi_valid);
        send_bits(s, (blcodes - 4) as u64, 4, &mut bi_buf, &mut bi_valid); /* not -3 as stated in appnote.txt */
        let bl_tree = (&raw const (*s).bl_tree).cast::<ct_data>();
        for &rank in BL_ORDER.iter().take(blcodes as usize) {
            send_bits(
                s,
                u64::from((*bl_tree.add(usize::from(rank))).dl),
                3,
                &mut bi_buf,
                &mut bi_valid,
            );
        }

        // Store back temp variables
        (*s).bi_buf = bi_buf;
        (*s).bi_valid = bi_valid as i32;

        send_tree(s, (&raw mut (*s).dyn_ltree).cast::<ct_data>(), lcodes - 1); /* literal tree */

        send_tree(s, (&raw mut (*s).dyn_dtree).cast::<ct_data>(), dcodes - 1); /* distance tree */
    }
}

/* ===========================================================================
 * Send a stored block
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for the block, and `buf` must
/// be valid for reads of `stored_len` bytes.
// Kept out of line, as it is across the C source files.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_tr_stored_block(
    s: *mut deflate_state,
    buf: *mut u8,
    stored_len: u32,
    last: c_int,
) {
    /* buf: input block */
    /* stored_len: length of input block */
    /* last: one if this is the last block for a file */
    // SAFETY: the caller guarantees the state and the input block are valid and the pending
    // buffer has room.
    unsafe {
        zng_tr_emit_tree(s, STORED_BLOCK, last); /* send block type */
        zng_tr_emit_align(s); /* align on byte boundary */
        cmpr_bits_align(s);
        put_short(s, stored_len as u16);
        put_short(s, !stored_len as u16);
        cmpr_bits_add(s, 32);
        sent_bits_add(s, 32);
        if stored_len != 0 {
            ptr::copy_nonoverlapping(
                buf,
                (*s).pending_buf.add((*s).pending as usize),
                stored_len as usize,
            );
            (*s).pending += stored_len;
            cmpr_bits_add(s, stored_len << 3);
            sent_bits_add(s, stored_len << 3);
        }
    }
}

/* ===========================================================================
 * Send one empty static block to give enough lookahead for inflate.
 * This takes 10 bits, of which 7 may remain in the bit buffer.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 16 more bytes.
// Kept out of line, as it is across the C source files.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_tr_align(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the state is valid and the pending buffer has room.
    unsafe {
        zng_tr_emit_tree(s, STATIC_TREES, 0);
        zng_tr_emit_end_block(s, static_ltree.as_ptr(), 0);
        zng_tr_flush_bits(s);
    }
}

/* ===========================================================================
 * Determine the best encoding for the current block: dynamic trees, static
 * trees or store, and write out the encoded block.
 */
/// # Safety
///
/// `s` must point to a deflate_state with a valid stream behind it, whose pending buffer has room
/// for the block. `buf` must be null or valid for reads of `stored_len` bytes.
// Kept out of line, as it is across the C source files.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_tr_flush_block(
    s: *mut deflate_state,
    buf: *mut u8,
    stored_len: u32,
    last: c_int,
) {
    /* buf: input block, or NULL if too old */
    /* stored_len: length of input block */
    /* last: one if this is the last block for a file */
    let mut opt_lenb; /* opt_len and static_len in bytes */
    let static_lenb;
    let mut max_blindex = 0; /* index of last bit length code of non zero freq */

    // SAFETY: the caller guarantees the state, its stream and the input block are valid and the
    // pending buffer has room.
    unsafe {
        /* Build the Huffman trees unless a stored block is forced */
        if unlikely((*s).sym_next == 0) {
            /* Emit an empty static tree block with no codes */
            opt_lenb = 0;
            static_lenb = 0;
            (*s).static_len = 7;
        } else if (*s).level > 0 {
            /* Check if the file is binary or text */
            if (*(*s).strm).data_type == Z_UNKNOWN {
                (*(*s).strm).data_type = detect_data_type(s);
            }

            /* Construct the literal and distance trees */
            build_tree(s, &raw mut (*s).l_desc);

            build_tree(s, &raw mut (*s).d_desc);
            /* At this point, opt_len and static_len are the total bit lengths of
             * the compressed block data, excluding the tree representations.
             */

            /* Build the bit length tree for the above two trees, and get the index
             * in bl_order of the last bit length code to send.
             */
            max_blindex = build_bl_tree(s);

            /* Determine the best encoding. Compute the block lengths in bytes. */
            opt_lenb = ((*s).opt_len + 3 + 7) >> 3;
            static_lenb = ((*s).static_len + 3 + 7) >> 3;

            if static_lenb <= opt_lenb || (*s).strategy == Z_FIXED {
                opt_lenb = static_lenb;
            }
        } else {
            debug_assert!(!buf.is_null(), "lost buf");
            /* force a stored block */
            opt_lenb = stored_len + 5;
            static_lenb = opt_lenb;
        }

        if stored_len + 4 <= opt_lenb && !buf.is_null() {
            /* 4: two words for the lengths
             * The test buf != NULL is only necessary if LIT_BUFSIZE > WSIZE.
             * Otherwise we can't have processed more than WSIZE input bytes since
             * the last block flush, because compression would have been
             * successful. If LIT_BUFSIZE <= WSIZE, it is never too late to
             * transform a block into a stored block.
             */
            zng_tr_stored_block(s, buf, stored_len, last);
        } else if static_lenb == opt_lenb {
            zng_tr_emit_tree(s, STATIC_TREES, last);
            compress_block(s, static_ltree.as_ptr(), static_dtree.as_ptr());
            cmpr_bits_add(s, (*s).static_len);
        } else {
            zng_tr_emit_tree(s, DYN_TREES, last);
            send_all_trees(
                s,
                (*s).l_desc.max_code + 1,
                (*s).d_desc.max_code + 1,
                max_blindex + 1,
            );
            compress_block(
                s,
                (&raw const (*s).dyn_ltree).cast::<ct_data>(),
                (&raw const (*s).dyn_dtree).cast::<ct_data>(),
            );
            cmpr_bits_add(s, (*s).opt_len);
        }
        debug_assert!(debug_bits_match(s), "bad compressed size");
        /* The above check is made mod 2^32, for files larger than 512 MB
         * and unsigned long implemented on 32 bits.
         */
        init_block(s);

        if last != 0 {
            zng_tr_emit_align(s);
        }
    }
}

/* ===========================================================================
 * Send the block data compressed using the given Huffman trees
 */
/* One 64-bit little-endian load at sx spans the next two symbols' dist fields
 * (bits 0..15, 24..39) and literals (bits 16..23, 40..47). The second symbol's dist
 * field alone separates a one-literal run from a two-literal one. */
#[cfg(not(feature = "lit-mem"))]
const LIT3_DIST1_MASK: u64 = 0x0000_00FF_FF00_0000;

/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for the block, and `ltree`
/// and `dtree` must hold a code for every symbol in its symbol buffer.
unsafe fn compress_block(s: *mut deflate_state, ltree: *const ct_data, dtree: *const ct_data) {
    /* ltree: literal tree */
    /* dtree: distance tree */
    // SAFETY: the caller guarantees the state and the trees are valid. The symbol buffer holds
    // sym_next bytes with readable padding behind them, and the pending buffer keeps room for
    // the 8 bytes that each flush stores.
    unsafe {
        let mut sx: usize = 0; /* running index in symbol buffers */

        /* Local pointers to avoid indirection */
        let sym_next = (*s).sym_next as usize;
        #[cfg(feature = "lit-mem")]
        let d_buf = (*s).d_buf;
        #[cfg(feature = "lit-mem")]
        let l_buf = (*s).l_buf;
        #[cfg(not(feature = "lit-mem"))]
        let sym_buf = (*s).sym_buf;
        // Rust cannot tell that the stores into the pending buffer leave the state alone, so the
        // pointer is read once here.
        let pending_buf = (*s).pending_buf;

        /* Keep the bit writer state in registers across the entire loop */
        let mut bi_buf = (*s).bi_buf;
        let mut bi_valid = (*s).bi_valid as u32;
        let mut pending = (*s).pending;

        if sym_next != 0 {
            loop {
                send_bits_flush(pending_buf, &mut bi_buf, &mut bi_valid, &mut pending);
                /* dist: distance of matched string */
                /* lc: match length or unmatched char (if dist == 0) */
                let dist;
                let lc;
                #[cfg(feature = "lit-mem")]
                {
                    dist = u32::from(*d_buf.add(sx));
                    lc = u32::from(*l_buf.add(sx));
                    sx += 1;
                }
                #[cfg(not(feature = "lit-mem"))]
                {
                    if OPTIMAL_CMP >= 32 {
                        let dist_lc = u32::from_le(zng_memread_4(sym_buf.add(sx)));
                        dist = dist_lc & 0xffff;
                        lc = (dist_lc >> 16) & 0xff;
                    } else {
                        dist = u32::from(*sym_buf.add(sx)) + (u32::from(*sym_buf.add(sx + 1)) << 8);
                        lc = u32::from(*sym_buf.add(sx + 2));
                    }
                    sx += 3;
                }
                if dist == 0 {
                    let mut bits: u64 = 0;
                    let mut nbits: u32 = 0;

                    send_code_merge(s, lc as usize, ltree, &mut bits, &mut nbits);
                    /* Accumulate up to 2 more consecutive literals into the same merge. Their
                     * codes are at most 15 bits each, so all three fit alongside the at most
                     * 7 bits the flush above leaves behind. */
                    #[cfg(not(feature = "lit-mem"))]
                    if OPTIMAL_CMP >= 64 && sx + 8 <= sym_next {
                        let next_syms = u64::from_le(zng_memread_8(sym_buf.add(sx)));

                        /* A dist field is zero exactly when that symbol is a literal */
                        if next_syms as u16 == 0 {
                            send_code_merge(
                                s,
                                ((next_syms >> 16) & 0xff) as usize,
                                ltree,
                                &mut bits,
                                &mut nbits,
                            );
                            sx += 3;

                            if next_syms & LIT3_DIST1_MASK == 0 {
                                send_code_merge(
                                    s,
                                    ((next_syms >> 40) & 0xff) as usize,
                                    ltree,
                                    &mut bits,
                                    &mut nbits,
                                );
                                sx += 3;
                            }
                        }
                    }
                    /* The codes were traced and counted as they accumulated */
                    debug_assert!(bi_valid + nbits <= 64, "bit buffer overflow");
                    bi_buf |= bits << bi_valid;
                    bi_valid += nbits;
                } else {
                    let mut match_bits_len = 0;
                    let match_bits = zng_assemble_dist(ltree, dtree, lc, dist, &mut match_bits_len);

                    send_bits_merge(s, match_bits, match_bits_len, &mut bi_buf, &mut bi_valid);
                } /* literal or match pair ? */

                /* Check for no overlay of pending_buf on needed symbols */
                #[cfg(feature = "lit-mem")]
                debug_assert!(
                    (pending as usize) < 2 * ((*s).lit_bufsize as usize + sx),
                    "pending_buf overflow"
                );
                #[cfg(not(feature = "lit-mem"))]
                debug_assert!(
                    (pending as usize) < (*s).lit_bufsize as usize + sx,
                    "pending_buf overflow"
                );

                if sx >= sym_next {
                    break;
                }
            }
        }

        (*s).pending = pending;
        zng_emit_end_block(s, ltree, &mut bi_buf, &mut bi_valid);

        /* Write back to state */
        (*s).bi_buf = bi_buf;
        (*s).bi_valid = bi_valid as i32;
    }
}

/* ===========================================================================
 * Check if the data type is TEXT or BINARY, using the following algorithm:
 * - TEXT if the two conditions below are satisfied:
 *    a) There are no non-portable control characters belonging to the
 *       "block list" (0..6, 14..25, 28..31).
 *    b) There is at least one printable character belonging to the
 *       "allow list" (9 {TAB}, 10 {LF}, 13 {CR}, 32..255).
 * - BINARY otherwise.
 * - The following partially-portable control characters form a
 *   "gray list" that is ignored in this detection algorithm:
 *   (7 {BEL}, 8 {BS}, 11 {VT}, 12 {FF}, 26 {SUB}, 27 {ESC}).
 * IN assertion: the fields Freq of dyn_ltree are set.
 */
/// # Safety
///
/// `s` must point to a deflate_state.
unsafe fn detect_data_type(s: *mut deflate_state) -> c_int {
    /* block_mask is the bit mask of block-listed bytes
     * set bits 0..6, 14..25, and 28..31
     * 0xf3ffc07f = binary 11110011111111111100000001111111
     */
    let mut block_mask: u32 = 0xf3ff_c07f;

    // SAFETY: the caller guarantees the state is valid, and nothing writes its literal tree here.
    let dyn_ltree = unsafe { &(*s).dyn_ltree };

    /* Check for non-textual ("block-listed") bytes. */
    for node in dyn_ltree.iter().take(32) {
        if block_mask & 1 != 0 && node.fc != 0 {
            return Z_BINARY;
        }
        block_mask >>= 1;
    }

    /* Check for textual ("allow-listed") bytes. */
    if dyn_ltree[9].fc != 0 || dyn_ltree[10].fc != 0 || dyn_ltree[13].fc != 0 {
        return Z_TEXT;
    }
    for node in dyn_ltree.iter().take(LITERALS).skip(32) {
        if node.fc != 0 {
            return Z_TEXT;
        }
    }

    /* There are no "block-listed" or "allow-listed" bytes:
     * this stream either is empty or has tolerated ("gray-listed") bytes only.
     */
    Z_BINARY
}

/* ===========================================================================
 * Flush the bit buffer, keeping at most 7 bits in it.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 8 more bytes.
// Kept out of line, as it is across the C source files.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_tr_flush_bits(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the state is valid and the pending buffer has room.
    unsafe {
        if (*s).bi_valid >= 48 {
            put_uint32(s, (*s).bi_buf as u32);
            put_short(s, ((*s).bi_buf >> 32) as u16);
            (*s).bi_buf >>= 48;
            (*s).bi_valid -= 48;
        } else if (*s).bi_valid >= 32 {
            put_uint32(s, (*s).bi_buf as u32);
            (*s).bi_buf >>= 32;
            (*s).bi_valid -= 32;
        }
        if (*s).bi_valid >= 16 {
            put_short(s, (*s).bi_buf as u16);
            (*s).bi_buf >>= 16;
            (*s).bi_valid -= 16;
        }
        if (*s).bi_valid >= 8 {
            put_byte(s, (*s).bi_buf as u8);
            (*s).bi_buf >>= 8;
            (*s).bi_valid -= 8;
        }
    }
}
