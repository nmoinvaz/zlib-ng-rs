//! Declarations for the parts of deflate.h and deflate.c that are still built from C.

#[cfg(feature = "zlib-compat")]
use core::ffi::c_char;
use core::ffi::{c_int, c_uint, c_ulong, c_void};

use crate::zbuild::prefix;
#[cfg(feature = "zlib-compat")]
use crate::zlib::ZLIB_VERSION;
use crate::zlib::z_stream;
use crate::zmemory::{zng_memwrite_2, zng_memwrite_4, zng_memwrite_8};
use crate::zutil::{MAX_BITS, STD_MAX_MATCH, STD_MIN_MATCH};

unsafe extern "C" {
    #[cfg(not(feature = "zlib-compat"))]
    #[link_name = "zng_deflateInit"]
    pub(crate) fn deflateInit(strm: *mut z_stream, level: i32) -> i32;
    #[cfg(feature = "zlib-compat")]
    fn deflateInit_(
        strm: *mut z_stream,
        level: i32,
        version: *const c_char,
        stream_size: i32,
    ) -> i32;
    #[link_name = prefix!("deflate")]
    pub(crate) fn deflate(strm: *mut z_stream, flush: i32) -> i32;
    #[link_name = prefix!("deflateEnd")]
    pub(crate) fn deflateEnd(strm: *mut z_stream) -> i32;
    #[link_name = prefix!("fill_window")]
    pub(crate) fn fill_window(s: *mut deflate_state);
    #[link_name = prefix!("flush_pending")]
    pub(crate) fn flush_pending(strm: *mut z_stream);
}

/// deflateInit is a macro in zlib.h to allow checking the zlib version
/// and the compiler's view of z_stream
///
/// # Safety
///
/// `strm` must be valid for reads and writes.
#[cfg(feature = "zlib-compat")]
#[allow(non_snake_case)]
#[inline]
pub(crate) unsafe fn deflateInit(strm: *mut z_stream, level: i32) -> i32 {
    // SAFETY: the caller guarantees strm is valid and the version is a NUL terminated string.
    unsafe {
        deflateInit_(
            strm,
            level,
            ZLIB_VERSION.as_ptr(),
            size_of::<z_stream>() as i32,
        )
    }
}

/// size of bit buffer in bi_buf
pub(crate) const BIT_BUF_SIZE: u32 = 64;

/// end of block literal code
pub(crate) const END_BLOCK: usize = 256;

/// Whether distances and literals/lengths are kept in separate buffers, LIT_MEM in the C sources
#[cfg_attr(not(feature = "c-layout"), allow(dead_code))]
pub(crate) const LIT_MEM: bool = cfg!(feature = "lit-mem");

/// number of length codes, not counting the special END_BLOCK code
pub(crate) const LENGTH_CODES: usize = 29;
/// number of literal bytes 0..255
pub(crate) const LITERALS: usize = 256;
/// number of Literal or Length codes, including the END_BLOCK code
pub(crate) const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;
/// number of distance codes
pub(crate) const D_CODES: usize = 30;
/// number of codes used to transfer the bit lengths
pub(crate) const BL_CODES: usize = 19;
/// maximum heap size
pub(crate) const HEAP_SIZE: usize = 2 * L_CODES + 1;

/// number of elements in hash table
pub(crate) const HASH_SIZE: usize = 65536;

/// The lowest level that uses the rolling hash
pub(crate) const MIN_ROLL_LEVEL: i32 = 9;
/// log2(HASH_SIZE)
pub(crate) const HASH_BITS: u32 = 16;

/// A Pos is an index in the character window.
#[allow(non_camel_case_types)]
pub(crate) type Pos = u16;

/// Data structure describing a single value and its code string.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct ct_data {
    /// frequency count or bit string
    pub(crate) fc: u16,
    /// father node in Huffman tree or length of bit string
    pub(crate) dl: u16,
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
pub(crate) struct tree_desc {
    /// the dynamic tree
    pub(crate) dyn_tree: *mut ct_data,
    /// largest code with non zero frequency
    pub(crate) max_code: c_int,
    /// the corresponding static tree
    pub(crate) stat_desc: *const c_void,
}

/// The state of a block after a compression function returns
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
pub enum block_state {
    /// block not completed, need more input or more output
    need_more,
    /// block flush performed
    block_done,
    /// finish started, need only more output at next deflate
    finish_started,
    /// finish done, accept no more input or output
    finish_done,
}

/// The fields of the C deflate_state up to the last one that the Rust sources use. The
/// structure is longer than this in C, so it must only be used through a pointer. The build
/// checks every field offset against the C definition.
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
pub struct deflate_state {
    /* Cacheline 0 */
    /// pointer back to this zlib stream
    pub(crate) strm: *mut z_stream,
    /// output still pending
    pub(crate) pending_buf: *mut u8,
    /// next pending byte to output to the stream
    pub(crate) pending_out: *mut u8,
    /// size of pending_buf
    pub(crate) pending_buf_size: u32,
    /// nb of bytes in the pending buffer
    pub(crate) pending: u32,
    /// bit 0 true for zlib, bit 1 true for gzip
    pub(crate) wrap: c_int,
    /// where in extra, name, or comment
    pub(crate) gzindex: u32,
    /// gzip header information to write
    pub(crate) gzhead: *mut c_void,
    /// as the name implies
    pub(crate) status: c_int,
    /// value of flush param for previous deflate call
    pub(crate) last_flush: c_int,
    /// Whether reproducible compression results are required.
    pub(crate) reproducible: c_int,

    /// Whether or not a block is currently open for the QUICK deflation scheme.
    /// This is set to 1 if there is an active block, or 0 if the block was just closed.
    pub(crate) block_open: c_uint,

    /* Cacheline 1 */
    /// number of valid bytes ahead in window
    pub(crate) lookahead: c_uint,
    /// start of string to insert
    pub(crate) strstart: c_uint,
    /// LZ77 window size (32K by default)
    pub(crate) w_size: c_uint,

    /// Window position at the beginning of the current output block.
    /// Gets negative when the window is moved backwards.
    pub(crate) block_start: c_int,

    /// High water mark offset in window for initialized bytes -- bytes above
    /// this are set to zero in order to avoid memory check warnings when
    /// longest match routines access bytes past the input.  This is then
    /// updated to the new high water mark.
    pub(crate) high_water: c_uint,

    /// Actual size of window: 2*wSize, except when the user input buffer
    /// is directly used as sliding window.
    pub(crate) window_size: c_uint,

    /// Sliding window. Input bytes are read into the second half of the window,
    /// and move to the first half later to keep a dictionary of at least wSize
    /// bytes. With this organization, matches are limited to a distance of
    /// wSize-STD_MAX_MATCH bytes, but this ensures that IO is always
    /// performed with a length multiple of the block size. Also, it limits
    /// the window size to 64K, which is quite useful on MSDOS.
    /// To do: use the user input buffer as sliding window.
    pub(crate) window: *mut u8,

    /// Link to older string with same hash index. To limit the size of this
    /// array to 64K, this link is maintained only for the last 32K strings.
    /// An index in this array is thus a window index modulo 32K.
    pub(crate) prev: *mut Pos,

    /// Heads of the hash chains or 0.
    pub(crate) head: *mut Pos,

    /// hash index of string to be inserted
    pub(crate) ins_h: u32,

    /// length of best match
    pub(crate) match_length: c_uint,
    /// set if previous match exists
    pub(crate) match_available: c_int,
    /// previous match (used by deflate_slow)
    pub(crate) prev_match: u32,

    /* Cacheline 2 */
    /// start of matching string
    pub(crate) match_start: c_uint,

    /// Length of the best match at previous step. Matches not greater than this
    /// are discarded. This is used in the lazy match evaluation.
    pub(crate) prev_length: c_uint,

    /// To speed up deflation, hash chains are never searched beyond this length.
    /// A higher limit improves compression ratio but degrades the speed.
    pub(crate) max_chain_length: c_uint,

    /// Attempt to find a better match only when the current match is strictly smaller
    /// than this value. This mechanism is used only for compression levels >= 4.
    pub(crate) max_lazy_match: c_uint,

    /// compression level (1..9)
    pub(crate) level: c_int,
    /// favor or force Huffman coding
    pub(crate) strategy: c_int,

    /// Use a faster search when the previous match is longer than this
    pub(crate) good_match: c_uint,
    /// Stop searching when current match exceeds this
    pub(crate) nice_match: c_int,
    /// bytes at end of window left to insert
    pub(crate) insert: c_uint,
    /// Last number of used bits when going to a byte boundary.
    pub(crate) bi_used: i32,
    /// Output buffer.
    /// Bits are inserted starting at the bottom (least significant bits).
    pub(crate) bi_buf: u64,
    /// Number of valid bits in bi_buf.
    /// All bits above the last valid bit are always zero.
    pub(crate) bi_valid: i32,
    /// Keeps Cacheline 3 aligned
    pub(crate) padding: [i32; 2],

    /* used by trees.c: */
    /// Size of match buffer for literals/lengths.
    pub(crate) lit_bufsize: c_uint,

    /* Cacheline 3 */
    /// buffer for distances
    #[cfg(feature = "lit-mem")]
    pub(crate) d_buf: *mut u16,
    /// buffer for literals/lengths
    #[cfg(feature = "lit-mem")]
    pub(crate) l_buf: *mut u8,
    /// buffer for distances and literals/lengths
    #[cfg(not(feature = "lit-mem"))]
    pub(crate) sym_buf: *mut u8,

    /// running index in symbol buffer
    pub(crate) sym_next: c_uint,
    /// symbol table full when sym_next reaches this
    pub(crate) sym_end: c_uint,

    /// bit length of current block with optimal trees
    pub(crate) opt_len: c_uint,
    /// bit length of current block with static trees
    pub(crate) static_len: c_uint,

    /// desc. for literal tree
    pub(crate) l_desc: tree_desc,
    /// desc. for distance tree
    pub(crate) d_desc: tree_desc,
    /// desc. for bit length tree
    pub(crate) bl_desc: tree_desc,

    /// number of codes at each bit length for an optimal tree
    pub(crate) bl_count: [u16; MAX_BITS + 1],

    /// build_tree() packed leaf entries
    pub(crate) pq_leaves: [u32; L_CODES + 1],
    /// build_tree() radix buffer and internal node FIFO
    pub(crate) pq_scratch: [u32; L_CODES + 1],

    /// literal and length tree
    pub(crate) dyn_ltree: [ct_data; HEAP_SIZE],
    /// distance tree
    pub(crate) dyn_dtree: [ct_data; 2 * D_CODES + 1],
    /// Huffman tree for bit lengths
    pub(crate) bl_tree: [ct_data; 2 * BL_CODES + 1],
}

#[allow(non_camel_case_types)]
pub(crate) type longest_match_func =
    unsafe extern "C" fn(s: *mut deflate_state, cur_match: u32) -> u32;
#[allow(non_camel_case_types)]
pub(crate) type insert_batch_func =
    unsafe extern "C" fn(s: *mut deflate_state, window: *mut u8, str: u32, count: u32);

// The level-selected function variants sit after the fields that only some builds have, so the
// build reads their offsets from the C sources.
#[cfg(feature = "c-layout")]
use crate::c_layout::{DEFLATE_STATE_INSERT_BATCH, DEFLATE_STATE_LONGEST_MATCH};
/// The offset for a plain cargo build, which has no C sources to ask.
#[cfg(not(feature = "c-layout"))]
const DEFLATE_STATE_LONGEST_MATCH: usize = size_of::<deflate_state>() + size_of::<usize>();
#[cfg(not(feature = "c-layout"))]
const DEFLATE_STATE_INSERT_BATCH: usize = DEFLATE_STATE_LONGEST_MATCH + size_of::<usize>();

/// Level-selected longest_match variant, set by lm_set_level()
///
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up.
#[inline(always)]
pub(crate) unsafe fn longest_match_fn(s: *const deflate_state) -> longest_match_func {
    // SAFETY: the caller guarantees s points to the full C structure, which holds the function
    // pointer at this offset.
    unsafe {
        s.cast::<u8>()
            .add(DEFLATE_STATE_LONGEST_MATCH)
            .cast::<longest_match_func>()
            .read()
    }
}

/// Level-selected insert_batch variant, set by lm_set_level()
///
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up.
#[inline(always)]
pub(crate) unsafe fn insert_batch_fn(s: *const deflate_state) -> insert_batch_func {
    // SAFETY: the caller guarantees s points to the full C structure, which holds the function
    // pointer at this offset.
    unsafe {
        s.cast::<u8>()
            .add(DEFLATE_STATE_INSERT_BATCH)
            .cast::<insert_batch_func>()
            .read()
    }
}

/// Whether the C sources are built with ZLIB_DEBUG, which adds the bit counts below to the state
#[cfg(feature = "c-layout")]
pub(crate) const ZLIB_DEBUG: bool = crate::c_layout::ZLIB_DEBUG != 0;
#[cfg(not(feature = "c-layout"))]
pub(crate) const ZLIB_DEBUG: bool = cfg!(debug_assertions);

#[cfg(feature = "c-layout")]
use crate::c_layout::{DEFLATE_STATE_BITS_SENT, DEFLATE_STATE_COMPRESSED_LEN};
/// The offsets for a plain cargo build, which has no C sources to ask.
#[cfg(not(feature = "c-layout"))]
const DEFLATE_STATE_COMPRESSED_LEN: usize = size_of::<deflate_state>() + size_of::<usize>();
#[cfg(not(feature = "c-layout"))]
const DEFLATE_STATE_BITS_SENT: usize = DEFLATE_STATE_COMPRESSED_LEN + size_of::<c_ulong>();

/// Adds to compressed_len, the total bit length of the compressed file mod 2^32. The count only
/// exists with ZLIB_DEBUG.
///
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up.
#[inline(always)]
pub(crate) unsafe fn cmpr_bits_add(s: *mut deflate_state, len: u32) {
    if ZLIB_DEBUG {
        // SAFETY: the caller guarantees s points to the full C structure, which holds the count
        // at this offset when it is built with ZLIB_DEBUG.
        unsafe {
            let count = s
                .cast::<u8>()
                .add(DEFLATE_STATE_COMPRESSED_LEN)
                .cast::<c_ulong>();
            count.write(count.read().wrapping_add(c_ulong::from(len)));
        }
    }
}

/// Adds to bits_sent, the bit length of the compressed data sent mod 2^32. The count only exists
/// with ZLIB_DEBUG.
///
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up.
#[inline(always)]
pub(crate) unsafe fn sent_bits_add(s: *mut deflate_state, bits: u32) {
    if ZLIB_DEBUG {
        // SAFETY: the caller guarantees s points to the full C structure, which holds the count
        // at this offset when it is built with ZLIB_DEBUG.
        unsafe {
            let count = s
                .cast::<u8>()
                .add(DEFLATE_STATE_BITS_SENT)
                .cast::<c_ulong>();
            count.write(count.read().wrapping_add(c_ulong::from(bits)));
        }
    }
}

/// Rounds bits_sent up to a byte boundary. The count only exists with ZLIB_DEBUG.
///
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up.
#[inline(always)]
pub(crate) unsafe fn sent_bits_align(s: *mut deflate_state) {
    if ZLIB_DEBUG {
        // SAFETY: the caller guarantees s points to the full C structure, which holds the count
        // at this offset when it is built with ZLIB_DEBUG.
        unsafe {
            let count = s
                .cast::<u8>()
                .add(DEFLATE_STATE_BITS_SENT)
                .cast::<c_ulong>();
            count.write(count.read().wrapping_add(7) & !7);
        }
    }
}

/* ===========================================================================
 * Output a byte on the stream.
 * IN assertion: there is enough room in pending_buf.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 1 more byte.
#[inline(always)]
pub(crate) unsafe fn put_byte(s: *mut deflate_state, c: u8) {
    // SAFETY: the caller guarantees the pending buffer has room.
    unsafe {
        *(*s).pending_buf.add((*s).pending as usize) = c;
        (*s).pending += 1;
    }
}

/* ===========================================================================
 * Output a short LSB first on the stream.
 * IN assertion: there is enough room in pending_buf.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 2 more bytes.
#[inline(always)]
pub(crate) unsafe fn put_short(s: *mut deflate_state, w: u16) {
    // SAFETY: the caller guarantees the pending buffer has room.
    unsafe {
        zng_memwrite_2((*s).pending_buf.add((*s).pending as usize), w.to_le());
        (*s).pending += 2;
    }
}

/* ===========================================================================
 * Output a 32-bit unsigned int LSB first on the stream.
 * IN assertion: there is enough room in pending_buf.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 4 more bytes.
#[inline(always)]
pub(crate) unsafe fn put_uint32(s: *mut deflate_state, dw: u32) {
    // SAFETY: the caller guarantees the pending buffer has room.
    unsafe {
        zng_memwrite_4((*s).pending_buf.add((*s).pending as usize), dw.to_le());
        (*s).pending += 4;
    }
}

/* ===========================================================================
 * Output a 64-bit unsigned int LSB first on the stream.
 * IN assertion: there is enough room in pending_buf.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 8 more bytes.
#[inline(always)]
pub(crate) unsafe fn put_uint64(s: *mut deflate_state, lld: u64) {
    // SAFETY: the caller guarantees the pending buffer has room.
    unsafe {
        zng_memwrite_8((*s).pending_buf.add((*s).pending as usize), lld.to_le());
        (*s).pending += 8;
    }
}

/// Minimum amount of lookahead, except at the end of the input file.
/// See deflate.c for comments about the STD_MIN_MATCH+1.
pub(crate) const MIN_LOOKAHEAD: u32 = (STD_MAX_MATCH + STD_MIN_MATCH + 1) as u32;

/// In order to simplify the code, particularly on 16 bit machines, match
/// distances are limited to MAX_DIST instead of WSIZE.
///
/// # Safety
///
/// `s` must point to a deflate_state.
#[inline(always)]
pub(crate) unsafe fn max_dist(s: *const deflate_state) -> c_uint {
    // SAFETY: the caller guarantees s is valid.
    unsafe { (*s).w_size - MIN_LOOKAHEAD }
}

/// Window mask: w_size is always a power of 2, so w_mask = w_size - 1
///
/// # Safety
///
/// `s` must point to a deflate_state.
#[inline(always)]
pub(crate) unsafe fn w_mask(s: *const deflate_state) -> c_uint {
    // SAFETY: the caller guarantees s is valid.
    unsafe { (*s).w_size - 1 }
}
