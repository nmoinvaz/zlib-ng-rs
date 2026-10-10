//! Port of the parts of trees_emit.h that the Rust sources need.

use crate::deflate::{
    BIT_BUF_SIZE, D_CODES, END_BLOCK, L_CODES, LITERALS, cmpr_bits_add, ct_data, deflate_state,
    put_byte, put_short, put_uint32, put_uint64, sent_bits_add, sent_bits_align,
};
use crate::trees::{d_code, dmask_extra, lmask_extra, zng_length_code};

/* If not enough room in bi_buf, use (valid) bits from bi_buf and
 * (64 - bi_valid) bits from value, leaving (width - (64-bi_valid))
 * unused bits in value.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 8 more bytes.
#[inline(always)]
pub(crate) unsafe fn send_bits(
    s: *mut deflate_state,
    val: u64,
    len: u32,
    bi_buf: &mut u64,
    bi_valid: &mut u32,
) {
    debug_assert!(*bi_valid <= 64, "Too many bits in bi_valid");
    let mut total_bits = *bi_valid + len;
    debug_assert!(len > 0 && len <= BIT_BUF_SIZE, "invalid length");
    // SAFETY: the caller guarantees the state is valid.
    unsafe { sent_bits_add(s, len) };

    /* Unconditionally shift and merge values into the buffer */
    *bi_buf |= val << *bi_valid;

    /* Check if the 64-bit boundary was crossed */
    if total_bits >= 64 {
        total_bits -= 64;
        // SAFETY: the caller guarantees the pending buffer has room.
        unsafe { put_uint64(s, *bi_buf) };

        /* Secure shift: prevent Undefined Behavior when bi_valid is 0 */
        /* If bi_valid is 0, we shift by 0 (via the mask) and overwrite bi_buf completely */
        *bi_buf = (val >> 1) >> (!*bi_valid & 63);
    }
    *bi_valid = total_bits;
}

/* Send a code of the given tree. c and tree must not have side effects */
/// # Safety
///
/// `tree` must hold more than `c` codes, and `s` must point to a deflate_state whose pending
/// buffer has room for 8 more bytes.
#[inline(always)]
unsafe fn send_code(
    s: *mut deflate_state,
    c: usize,
    tree: *const ct_data,
    bi_buf: &mut u64,
    bi_valid: &mut u32,
) {
    // SAFETY: the caller guarantees c is inside the tree and the pending buffer has room.
    unsafe {
        let code = *tree.add(c);
        send_bits(s, u64::from(code.fc), u32::from(code.dl), bi_buf, bi_valid);
    }
}

/* ===========================================================================
 * Flush the bit buffer and align the output on a byte boundary
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 8 more bytes.
#[inline]
pub(crate) unsafe fn bi_windup(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the state is valid and the pending buffer has room.
    unsafe {
        if (*s).bi_valid > 56 {
            put_uint64(s, (*s).bi_buf);
        } else {
            if (*s).bi_valid > 24 {
                put_uint32(s, (*s).bi_buf as u32);
                (*s).bi_buf >>= 32;
                (*s).bi_valid -= 32;
            }
            if (*s).bi_valid > 8 {
                put_short(s, (*s).bi_buf as u16);
                (*s).bi_buf >>= 16;
                (*s).bi_valid -= 16;
            }
            if (*s).bi_valid > 0 {
                put_byte(s, (*s).bi_buf as u8);
            }
        }
        (*s).bi_used = (((*s).bi_valid - 1) & 7) + 1;
        (*s).bi_buf = 0;
        (*s).bi_valid = 0;
    }
}

/* ===========================================================================
 * Emit literal code
 */
/// # Safety
///
/// `ltree` must hold a code for `c`, and `s` must point to a deflate_state whose pending buffer
/// has room for 8 more bytes.
#[inline(always)]
pub(crate) unsafe fn zng_emit_lit(
    s: *mut deflate_state,
    ltree: *const ct_data,
    c: u32,
    bi_buf: &mut u64,
    bi_valid: &mut u32,
) {
    // SAFETY: the caller upholds the contract of send_code.
    unsafe { send_code(s, c as usize, ltree, bi_buf, bi_valid) };
}

/* ===========================================================================
 * Assemble a match's length code + extra bits + distance code + extra bits into
 * a single bit string, at most 48 bits. Returns the bits, length via *bits_len.
 */
/// # Safety
///
/// `ltree` must hold L_CODES codes and `dtree` D_CODES codes. `lc` must be a match length minus
/// STD_MIN_MATCH and `dist` a match distance from 1 to 32768.
#[inline(always)]
pub(crate) unsafe fn zng_assemble_dist(
    ltree: *const ct_data,
    dtree: *const ct_data,
    lc: u32,
    dist: u32,
    bits_len: &mut u32,
) -> u64 {
    // SAFETY: zng_length_code only holds length codes below LENGTH_CODES, and d_code only returns
    // distance codes below D_CODES, so every index is inside its table.
    unsafe {
        /* 1. Process Length Code */
        let code = zng_length_code[usize::from(lc as u8)];
        let c = usize::from(code) + LITERALS + 1;
        debug_assert!(c < L_CODES, "bad l_code");

        /*    Send length code, len is the match length - STD_MIN_MATCH */
        let lcode = *ltree.add(c);
        let mut match_bits = u64::from(lcode.fc);
        let mut match_bits_len = u32::from(lcode.dl);

        /* 2. Get extra bits count and mask */
        // Contains both mask and extra, can safely be used directly as mask
        // due to extra bits being outside the range of lc and dist data.
        let mask_ext = u32::from(*lmask_extra.get_unchecked(usize::from(code)));
        let extra = mask_ext >> 8;

        /*    Send length extra bits */
        match_bits |= u64::from(lc & mask_ext) << match_bits_len;
        match_bits_len += extra;

        /* 3. Process Distance Code */
        let dist = dist - 1; /* dist is now the match distance - 1 */
        let code = d_code(dist);
        debug_assert!(usize::from(code) < D_CODES, "bad d_code");

        /*    Send distance code */
        let dcode = *dtree.add(usize::from(code));
        match_bits |= u64::from(dcode.fc) << match_bits_len;
        match_bits_len += u32::from(dcode.dl);

        /* 4. Get extra bits count and mask */
        let mask_ext = *dmask_extra.get_unchecked(usize::from(code));
        let extra = mask_ext >> 16;

        /*    Send dist extra bits */
        match_bits |= u64::from(dist & mask_ext) << match_bits_len;
        match_bits_len += extra;

        *bits_len = match_bits_len;
        match_bits
    }
}

/* ===========================================================================
 * Emit match distance/length code
 */
/// # Safety
///
/// The contract of zng_assemble_dist applies, and `s` must point to a deflate_state whose pending
/// buffer has room for 8 more bytes.
#[inline(always)]
pub(crate) unsafe fn zng_emit_dist(
    s: *mut deflate_state,
    ltree: *const ct_data,
    dtree: *const ct_data,
    lc: u32,
    dist: u32,
    bi_buf: &mut u64,
    bi_valid: &mut u32,
) -> u32 {
    let mut match_bits_len = 0;
    // SAFETY: the caller upholds the contracts of zng_assemble_dist and send_bits.
    unsafe {
        let match_bits = zng_assemble_dist(ltree, dtree, lc, dist, &mut match_bits_len);

        send_bits(s, match_bits, match_bits_len, bi_buf, bi_valid);
    }

    match_bits_len
}

/* ===========================================================================
 * Emit end block
 */
/// # Safety
///
/// `ltree` must hold a code for END_BLOCK, and `s` must point to a deflate_state whose pending
/// buffer has room for 8 more bytes.
#[inline(always)]
pub(crate) unsafe fn zng_emit_end_block(
    s: *mut deflate_state,
    ltree: *const ct_data,
    bi_buf: &mut u64,
    bi_valid: &mut u32,
) {
    // SAFETY: the caller upholds the contract of send_code.
    unsafe { send_code(s, END_BLOCK, ltree, bi_buf, bi_valid) };
}

/* ===========================================================================
 * Emit literal and count bits
 */
/// # Safety
///
/// The contract of zng_emit_lit applies.
#[inline(always)]
pub(crate) unsafe fn zng_tr_emit_lit(s: *mut deflate_state, ltree: *const ct_data, c: u32) {
    // SAFETY: the caller upholds the contract of zng_emit_lit.
    unsafe {
        let mut bi_buf = (*s).bi_buf;
        let mut bi_valid = (*s).bi_valid as u32;
        zng_emit_lit(s, ltree, c, &mut bi_buf, &mut bi_valid);
        (*s).bi_buf = bi_buf;
        (*s).bi_valid = bi_valid as i32;
        cmpr_bits_add(s, u32::from((*ltree.add(c as usize)).dl));
    }
}

/* ===========================================================================
 * Emit match and count bits
 */
/// # Safety
///
/// The contract of zng_emit_dist applies.
#[inline(always)]
pub(crate) unsafe fn zng_tr_emit_dist(
    s: *mut deflate_state,
    ltree: *const ct_data,
    dtree: *const ct_data,
    lc: u32,
    dist: u32,
) {
    // SAFETY: the caller upholds the contract of zng_emit_dist.
    unsafe {
        let mut bi_buf = (*s).bi_buf;
        let mut bi_valid = (*s).bi_valid as u32;
        let bits = zng_emit_dist(s, ltree, dtree, lc, dist, &mut bi_buf, &mut bi_valid);
        (*s).bi_buf = bi_buf;
        (*s).bi_valid = bi_valid as i32;
        cmpr_bits_add(s, bits);
    }
}

/* ===========================================================================
 * Emit start of block
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 8 more bytes.
#[inline(always)]
pub(crate) unsafe fn zng_tr_emit_tree(s: *mut deflate_state, block_type: u32, last: bool) {
    // SAFETY: the caller guarantees the state is valid and the pending buffer has room.
    unsafe {
        let mut bi_valid = (*s).bi_valid as u32;
        let mut bi_buf = (*s).bi_buf;
        let header_bits = (block_type << 1) + u32::from(last);
        send_bits(s, u64::from(header_bits), 3, &mut bi_buf, &mut bi_valid);
        cmpr_bits_add(s, 3);
        (*s).bi_valid = bi_valid as i32;
        (*s).bi_buf = bi_buf;
    }
}

/* ===========================================================================
 * Align bit buffer on a byte boundary and count bits
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 8 more bytes.
#[inline(always)]
pub(crate) unsafe fn zng_tr_emit_align(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the state is valid and the pending buffer has room.
    unsafe {
        bi_windup(s); /* align on byte boundary */
        sent_bits_align(s);
    }
}

/* ===========================================================================
 * Emit an end block and align bit buffer if last block
 */
/// # Safety
///
/// `ltree` must hold a code for END_BLOCK, and `s` must point to a deflate_state whose pending
/// buffer has room for 16 more bytes.
#[inline(always)]
pub(crate) unsafe fn zng_tr_emit_end_block(
    s: *mut deflate_state,
    ltree: *const ct_data,
    last: bool,
) {
    // SAFETY: the caller upholds the contracts of zng_emit_end_block and zng_tr_emit_align.
    unsafe {
        let mut bi_buf = (*s).bi_buf;
        let mut bi_valid = (*s).bi_valid as u32;
        zng_emit_end_block(s, ltree, &mut bi_buf, &mut bi_valid);
        (*s).bi_buf = bi_buf;
        (*s).bi_valid = bi_valid as i32;
        cmpr_bits_add(s, 7);
        if last {
            zng_tr_emit_align(s);
        }
    }
}
