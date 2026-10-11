//! inflate_p.h -- Private inline functions and macros shared with more than one deflate method

/* Huffman code table entry format for length/distance codes (op & 16 set):
 *   bits = code_bits + extra_bits (combined for single-shift decode)
 *   op   = 16 | code_bits
 *   val  = base value
 *
 * For literals (op == 0): bits = code_bits, val = literal byte
 */

/* Build combined op field: preserves extra if not len/dist, else combines with code_bits */
#[inline(always)]
pub(crate) fn combine_op(extra: u32, code_bits: u8) -> u8 {
    if extra & 16 != 0 {
        code_bits | 16
    } else {
        extra as u8
    }
}

/* Build combined bits field: code_bits + extra_bits from extra's low nibble */
#[inline(always)]
pub(crate) fn combine_bits(code_bits: u8, extra: u32) -> u8 {
    code_bits.wrapping_add((extra & 15) as u8)
}
