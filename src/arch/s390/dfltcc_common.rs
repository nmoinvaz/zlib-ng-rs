//! Port of the parts of dfltcc_common.h that the Rust sources need.

/*
   Sizes of deflate block parts.
*/
const DFLTCC_BLOCK_HEADER_BITS: usize = 3;
const DFLTCC_HLITS_COUNT_BITS: usize = 5;
const DFLTCC_HDISTS_COUNT_BITS: usize = 5;
const DFLTCC_HCLENS_COUNT_BITS: usize = 4;
const DFLTCC_MAX_HCLENS: usize = 19;
const DFLTCC_HCLEN_BITS: usize = 3;
const DFLTCC_MAX_HLITS: usize = 286;
const DFLTCC_MAX_HDISTS: usize = 30;
const DFLTCC_MAX_HLIT_HDIST_BITS: usize = 7;
const DFLTCC_MAX_SYMBOL_BITS: usize = 16;
const DFLTCC_MAX_EOBS_BITS: usize = 15;
const DFLTCC_MAX_PADDING_BITS: usize = 7;

#[inline(always)]
pub(crate) const fn deflate_bound_complen(source_len: usize) -> usize {
    (DFLTCC_BLOCK_HEADER_BITS
        + DFLTCC_HLITS_COUNT_BITS
        + DFLTCC_HDISTS_COUNT_BITS
        + DFLTCC_HCLENS_COUNT_BITS
        + DFLTCC_MAX_HCLENS * DFLTCC_HCLEN_BITS
        + (DFLTCC_MAX_HLITS + DFLTCC_MAX_HDISTS) * DFLTCC_MAX_HLIT_HDIST_BITS)
        .wrapping_add(source_len.wrapping_mul(DFLTCC_MAX_SYMBOL_BITS))
        .wrapping_add(DFLTCC_MAX_EOBS_BITS + DFLTCC_MAX_PADDING_BITS)
        >> 3
}
