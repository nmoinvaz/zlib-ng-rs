//! deflate.c -- compress data using the deflation algorithm
//! Copyright (C) 1995-2026 Jean-loup Gailly and Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

/*
 *  ALGORITHM
 *
 *      The "deflation" process depends on being able to identify portions
 *      of the input text which are identical to earlier input (within a
 *      sliding window trailing behind the input currently being processed).
 *
 *      The most straightforward technique turns out to be the fastest for
 *      most input files: try all possible matches and select the longest.
 *      The key feature of this algorithm is that insertions into the string
 *      dictionary are very simple and thus fast, and deletions are avoided
 *      completely. Insertions are performed at each input character, whereas
 *      string matches are performed only when the previous match ends. So it
 *      is preferable to spend more time in matches to allow very fast string
 *      insertions and avoid deletions. The matching algorithm for small
 *      strings is inspired from that of Rabin & Karp. A brute force approach
 *      is used to find longer strings when a small match has been found.
 *      A similar algorithm is used in comic (by Jan-Mark Wams) and freeze
 *      (by Leonid Broukhis).
 *         A previous version of this file used a more sophisticated algorithm
 *      (by Fiala and Greene) which is guaranteed to run in linear amortized
 *      time, but has a larger average cost, uses more memory and is patented.
 *      However the F&G algorithm may be faster for some highly redundant
 *      files if the parameter max_chain_length (described below) is too large.
 *
 *  ACKNOWLEDGEMENTS
 *
 *      The idea of lazy evaluation of matches is due to Jan-Mark Wams, and
 *      I found it in 'freeze' written by Leonid Broukhis.
 *      Thanks to many people for bug reports and testing.
 *
 *  REFERENCES
 *
 *      Deutsch, L.P.,"DEFLATE Compressed Data Format Specification".
 *      Available at https://datatracker.ietf.org/doc/html/rfc1951
 *
 *      A description of the Rabin and Karp algorithm is given in the book
 *         "Algorithms" by R. Sedgewick, Addison-Wesley, p252.
 *
 *      Fiala,E.R., and Greene,D.H.
 *         Data Compression with Finite Windows, Comm.ACM, 32,4 (1989) 490-595
 *
 */

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use core::ptr;

#[cfg(feature = "s390-dfltcc-deflate")]
use crate::arch::s390::dfltcc_deflate;
use crate::crc32::crc32_small;
use crate::deflate_fast::deflate_fast;
use crate::deflate_huff::deflate_huff;
#[cfg(not(feature = "no-quick-strategy"))]
use crate::deflate_medium::{deflate_medium, deflate_medium_fizzle};
use crate::deflate_p::{flush_pending_inline, read_buf};
#[cfg(not(feature = "no-quick-strategy"))]
use crate::deflate_quick::deflate_quick;
use crate::deflate_rle::deflate_rle;
use crate::deflate_slow::deflate_slow;
use crate::deflate_stored::deflate_stored;
use crate::functable;
use crate::insert_string::{insert_knuth_batch, insert_knuth_batch_head, insert_roll_batch};
use crate::insert_string_p::{insert_knuth, insert_knuth_head, update_hash_roll};
use crate::trees::{
    static_tree_desc, zng_tr_align, zng_tr_flush_bits, zng_tr_init, zng_tr_stored_block,
};
use crate::zbuild::{prefix, unlikely, z_checksum_t};
use crate::zconf::{MAX_MEM_LEVEL, MAX_WBITS, MIN_WBITS};
#[cfg(feature = "zlib-compat")]
use crate::zlib::ZLIB_VERSION;
use crate::zlib::{
    Z_BLOCK, Z_BUF_ERROR, Z_DATA_ERROR, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY, Z_DEFLATED,
    Z_FINISH, Z_FIXED, Z_FULL_FLUSH, Z_HUFFMAN_ONLY, Z_MEM_ERROR, Z_NO_FLUSH, Z_OK,
    Z_PARTIAL_FLUSH, Z_RLE, Z_STREAM_END, Z_STREAM_ERROR, Z_UNKNOWN, Z_VERSION_ERROR, free_func,
    gz_header, internal_state, z_stream,
};
#[cfg(not(feature = "zlib-compat"))]
use crate::zlib::{
    Z_DEFLATE_LEVEL, Z_DEFLATE_REPRODUCIBLE, Z_DEFLATE_STRATEGY, zng_deflate_param_value,
};
use crate::zmemory::{zng_memwrite_2, zng_memwrite_4, zng_memwrite_8};
use crate::zutil::{
    ADLER32_INITIAL_VALUE, CRC32_INITIAL_VALUE, DEF_MEM_LEVEL, GZIP_WRAPLEN, MAX_BITS, PRESET_DICT,
    STD_MAX_MATCH, STD_MIN_MATCH, ZLIB_WRAPLEN, check_ver_stsize, err_return, zcalloc, zcfree,
};
#[cfg(not(feature = "no-quick-strategy"))]
use crate::zutil::{DEFLATE_BLOCK_OVERHEAD, deflate_quick_overhead};

const MIN_MATCH: u32 = STD_MIN_MATCH as u32;

/* Stream status */
/// zlib header -> BUSY_STATE
pub(crate) const INIT_STATE: c_int = 1;
/// gzip header -> BUSY_STATE | EXTRA_STATE
pub(crate) const GZIP_STATE: c_int = 4;
/// gzip extra block -> NAME_STATE
pub(crate) const EXTRA_STATE: c_int = 5;
/// gzip file name -> COMMENT_STATE
pub(crate) const NAME_STATE: c_int = 6;
/// gzip comment -> HCRC_STATE
pub(crate) const COMMENT_STATE: c_int = 7;
/// gzip header CRC -> BUSY_STATE
pub(crate) const HCRC_STATE: c_int = 8;
/// deflate -> FINISH_STATE
pub(crate) const BUSY_STATE: c_int = 2;
/// stream complete
pub(crate) const FINISH_STATE: c_int = 3;
pub(crate) const MAX_STATE: c_int = HCRC_STATE;

/// Number of bytes after end of data in window to initialize in order to avoid
/// memory checker errors from longest match routines
const WIN_INIT: u32 = STD_MAX_MATCH as u32;

/// The pending buffer holds this many times lit_bufsize bytes
#[cfg(feature = "lit-mem")]
pub(crate) const LIT_BUFS: usize = 5;
#[cfg(not(feature = "lit-mem"))]
pub(crate) const LIT_BUFS: usize = 4;

/// DFLTCC instructions require window to be page-aligned
#[cfg(feature = "s390-dfltcc-deflate")]
pub(crate) const WINDOW_PAD_SIZE: usize = 4096;
#[cfg(not(feature = "s390-dfltcc-deflate"))]
pub(crate) const WINDOW_PAD_SIZE: usize = 64;

/// The history buffer of DFLTCC
#[cfg(feature = "s390-dfltcc-deflate")]
const HB_SIZE: usize = 1 << 15;

/// Struct for memory allocation handling
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct deflate_allocs {
    buf_start: *mut u8,
    zfree: free_func,
    state: *mut deflate_state,
    window: *mut u8,
    pending_buf: *mut u8,
    prev: *mut Pos,
    head: *mut Pos,
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
    pub(crate) stat_desc: *const static_tree_desc,
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
    pub(crate) gzhead: *mut gz_header,
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

    pub(crate) alloc_bufs: *mut deflate_allocs,
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

/// The size of the whole C structure, and the code that gzip headers carry for this system
#[cfg(feature = "c-layout")]
use crate::c_layout::{DEFLATE_STATE_SIZE, OS_CODE};
#[cfg(not(feature = "c-layout"))]
const DEFLATE_STATE_SIZE: usize =
    (DEFLATE_STATE_INSERT_BATCH + size_of::<usize>() + 80).next_multiple_of(64);
#[cfg(not(feature = "c-layout"))]
const OS_CODE: u8 = 3;

/// # Safety
///
/// `s` must point to a deflate_state.
#[inline(always)]
unsafe fn set_longest_match(s: *mut deflate_state, f: longest_match_func) {
    // SAFETY: the caller guarantees s points to the full C structure, which holds the function
    // pointer at this offset.
    unsafe {
        s.cast::<u8>()
            .add(DEFLATE_STATE_LONGEST_MATCH)
            .cast::<longest_match_func>()
            .write(f)
    };
}

/// # Safety
///
/// `s` must point to a deflate_state.
#[inline(always)]
unsafe fn set_insert_batch(s: *mut deflate_state, f: insert_batch_func) {
    // SAFETY: the caller guarantees s points to the full C structure, which holds the function
    // pointer at this offset.
    unsafe {
        s.cast::<u8>()
            .add(DEFLATE_STATE_INSERT_BATCH)
            .cast::<insert_batch_func>()
            .write(f)
    };
}

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

/// Rounds compressed_len up to a byte boundary. The count only exists with ZLIB_DEBUG.
///
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up.
#[inline(always)]
pub(crate) unsafe fn cmpr_bits_align(s: *mut deflate_state) {
    if ZLIB_DEBUG {
        // SAFETY: the caller guarantees s points to the full C structure, which holds the count
        // at this offset when it is built with ZLIB_DEBUG.
        unsafe {
            let count = s
                .cast::<u8>()
                .add(DEFLATE_STATE_COMPRESSED_LEN)
                .cast::<c_ulong>();
            count.write(count.read().wrapping_add(7) & !7);
        }
    }
}

/// Clears compressed_len and bits_sent, which only exist with ZLIB_DEBUG.
///
/// # Safety
///
/// `s` must point to a deflate_state.
#[inline(always)]
pub(crate) unsafe fn debug_bits_reset(s: *mut deflate_state) {
    if ZLIB_DEBUG {
        // SAFETY: the caller guarantees s points to the full C structure, which holds the
        // counts at these offsets when it is built with ZLIB_DEBUG.
        unsafe {
            s.cast::<u8>()
                .add(DEFLATE_STATE_COMPRESSED_LEN)
                .cast::<c_ulong>()
                .write(0);
            s.cast::<u8>()
                .add(DEFLATE_STATE_BITS_SENT)
                .cast::<c_ulong>()
                .write(0);
        }
    }
}

/// Whether compressed_len equals bits_sent. Always true without ZLIB_DEBUG, which has no counts.
///
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
#[inline(always)]
pub(crate) unsafe fn debug_bits_match(s: *mut deflate_state) -> bool {
    if ZLIB_DEBUG {
        // SAFETY: the caller guarantees s points to the full C structure, which holds the
        // counts at these offsets when it is built with ZLIB_DEBUG.
        unsafe {
            let compressed_len = s
                .cast::<u8>()
                .add(DEFLATE_STATE_COMPRESSED_LEN)
                .cast::<c_ulong>()
                .read();
            let bits_sent = s
                .cast::<u8>()
                .add(DEFLATE_STATE_BITS_SENT)
                .cast::<c_ulong>()
                .read();
            compressed_len == bits_sent
        }
    } else {
        true
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

/* ===========================================================================
 * Output a short MSB first on the stream.
 * IN assertion: there is enough room in pending_buf.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 2 more bytes.
#[inline(always)]
unsafe fn put_short_msb(s: *mut deflate_state, w: u16) {
    // SAFETY: the caller guarantees the pending buffer has room.
    unsafe {
        zng_memwrite_2((*s).pending_buf.add((*s).pending as usize), w.to_be());
        (*s).pending += 2;
    }
}

/* ===========================================================================
 * Output a 32-bit unsigned int MSB first on the stream.
 * IN assertion: there is enough room in pending_buf.
 */
/// # Safety
///
/// `s` must point to a deflate_state whose pending buffer has room for 4 more bytes.
#[inline(always)]
unsafe fn put_uint32_msb(s: *mut deflate_state, dw: u32) {
    // SAFETY: the caller guarantees the pending buffer has room.
    unsafe {
        zng_memwrite_4((*s).pending_buf.add((*s).pending as usize), dw.to_be());
        (*s).pending += 4;
    }
}

/// Window bits: log2(w_size), computed from w_size since w_size is a power of 2
///
/// # Safety
///
/// `s` must point to a deflate_state.
#[inline(always)]
unsafe fn w_bits(s: *const deflate_state) -> u32 {
    // SAFETY: the caller guarantees s is valid.
    unsafe { (*s).w_size.trailing_zeros() }
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

/* ===========================================================================
 *  The functions of deflate.c
 */

/// If you use the zlib library in a product, an acknowledgment is welcome
/// in the documentation of your product. If for some reason you cannot
/// include such an acknowledgment, I would appreciate that you keep this
/// copyright string in the executable of your product.
const COPYRIGHT: &[u8] = b" deflate 1.3.2 Copyright 1995-2026 Jean-loup Gailly and Mark Adler \0";

#[allow(non_upper_case_globals)]
#[used]
#[unsafe(export_name = prefix!("deflate_copyright"))]
pub static deflate_copyright: [u8; COPYRIGHT.len()] = {
    let mut text = [0; COPYRIGHT.len()];
    let mut i = 0;
    while i < text.len() {
        text[i] = COPYRIGHT[i];
        i += 1;
    }
    text
};

/* ===========================================================================
 * Local data
 */

/* Values for max_lazy_match, good_match and max_chain_length, depending on
 * the desired pack level (0..9). The values given below have been tuned to
 * exclude worst case performance for pathological files. Better values may be
 * found for specific files.
 */
#[allow(non_camel_case_types)]
type compress_func = unsafe extern "C" fn(s: *mut deflate_state, flush: c_int) -> block_state;

#[allow(non_camel_case_types)]
struct config {
    /// reduce lazy search above this match length
    good_length: u16,
    /// do not perform lazy search above this match length
    max_lazy: u16,
    /// quit search above this match length
    nice_length: u16,
    max_chain: u16,
    func: compress_func,
}

const fn config(
    good_length: u16,
    max_lazy: u16,
    nice_length: u16,
    max_chain: u16,
    func: compress_func,
) -> config {
    config {
        good_length,
        max_lazy,
        nice_length,
        max_chain,
        func,
    }
}

#[rustfmt::skip]
static CONFIGURATION_TABLE: [config; 10] = [
    /*             good lazy nice chain */
    /* 0 */ config(0,    0,   0,    0, deflate_stored), /* store only */

    #[cfg(feature = "no-quick-strategy")]
    /* 1 */ config(4,    4,   8,    4, deflate_fast), /* max speed, no lazy matches */
    #[cfg(feature = "no-quick-strategy")]
    /* 2 */ config(4,    5,  16,    8, deflate_fast),
    #[cfg(not(feature = "no-quick-strategy"))]
    /* 1 */ config(0,    0,   0,    0, deflate_quick),
    #[cfg(not(feature = "no-quick-strategy"))]
    /* 2 */ config(4,    4,   8,    4, deflate_fast), /* max speed, no lazy matches */

    #[cfg(feature = "no-quick-strategy")]
    /* 3 */ config(4,    6,  32,   32, deflate_fast),
    #[cfg(feature = "no-quick-strategy")]
    /* 4 */ config(4,    4,  16,   16, deflate_slow), /* lazy matches */
    #[cfg(feature = "no-quick-strategy")]
    /* 5 */ config(8,   16,  32,   32, deflate_slow),
    #[cfg(feature = "no-quick-strategy")]
    /* 6 */ config(8,   16, 128,  128, deflate_slow),
    #[cfg(not(feature = "no-quick-strategy"))]
    /* 3 */ config(4,    6,  16,    6, deflate_medium),
    #[cfg(not(feature = "no-quick-strategy"))]
    /* 4 */ config(4,   12,  32,   24, deflate_medium), /* lazy matches */
    #[cfg(not(feature = "no-quick-strategy"))]
    /* 5 */ config(8,   16,  32,   32, deflate_medium_fizzle),
    #[cfg(not(feature = "no-quick-strategy"))]
    /* 6 */ config(8,   16, 128,  128, deflate_medium_fizzle),

    /* 7 */ config(8,   32, 128,  256, deflate_slow),
    /* 8 */ config(32, 128, 258, 1024, deflate_slow),
    /* 9 */ config(32, 258, 258, 4096, deflate_slow), /* max compression */
];

/* Note: the deflate() code requires max_lazy >= STD_MIN_MATCH and max_chain >= 4
 * For deflate_fast() (levels <= 3) good is ignored and lazy has a different
 * meaning.
 */

/// The configuration of a level that the caller has checked to be 0..9
///
/// # Safety
///
/// `level` must be from 0 to 9.
#[inline(always)]
unsafe fn configuration(level: c_int) -> &'static config {
    // SAFETY: the caller guarantees the level is inside the table.
    unsafe { CONFIGURATION_TABLE.get_unchecked(level as usize) }
}

/* Level 1 uses deflate_quick, which only reads the hash chain head, so it can
 * skip prev maintenance. When quick is compiled out level 1 falls back to
 * deflate_fast, which walks the chains like every other level. */
const HAVE_QUICK_STRATEGY: bool = cfg!(not(feature = "no-quick-strategy"));

/// rank Z_BLOCK between Z_NO_FLUSH and Z_PARTIAL_FLUSH
#[inline(always)]
const fn rank(f: c_int) -> c_int {
    (f * 2) - (if f > 4 { 9 } else { 0 })
}

/* ===========================================================================
 * Initialize the hash table. prev[] will be initialized on the fly.
 */
/// # Safety
///
/// `s` must point to a deflate_state with a valid head table.
#[inline(always)]
unsafe fn clear_hash(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the head table holds HASH_SIZE entries.
    unsafe { ptr::write_bytes((*s).head, 0, HASH_SIZE) };
}

/* Configurations that never read the hash table. When deflateParams() switches
 * to a configuration that does read it, it rebuilds the table from the window.
 */
#[inline(always)]
const fn hashless(level: c_int, strategy: c_int) -> bool {
    level == 0 || strategy == Z_HUFFMAN_ONLY || strategy == Z_RLE
}

/* Extra bytes reserved between the pending buffer and the symbol buffers, and at
 * the end of the pending allocation. send_bits_flush stores 8 bytes unconditionally but
 * only advances past the complete ones, so its stores reach up to 7 bytes beyond the
 * logical output position, which may otherwise clobber unread symbols as the output
 * chases the symbol buffer, or run past the allocation. */
const PENDING_BUF_PAD: usize = 8;

#[inline(always)]
const fn pending_buf_bytes(lit_bufsize: usize) -> usize {
    (lit_bufsize * LIT_BUFS) + 1 + PENDING_BUF_PAD
}

/// The padding that brings a position to a multiple of pad, PADSZ in C
#[inline(always)]
const fn padsz(bpos: usize, pad: usize) -> usize {
    (pad - (bpos % pad)) % pad
}

#[inline(always)]
const fn pad_16(bpos: usize) -> usize {
    bpos + padsz(bpos, 16)
}

#[inline(always)]
const fn pad_64(bpos: usize) -> usize {
    bpos + padsz(bpos, 64)
}

#[inline(always)]
const fn pad_window(bpos: usize) -> usize {
    bpos + padsz(bpos, WINDOW_PAD_SIZE)
}

/// Adjust the window size for the arch-specific deflate code.
#[inline(always)]
const fn deflate_adjust_window_size(n: usize) -> usize {
    #[cfg(feature = "s390-dfltcc-deflate")]
    return if n > HB_SIZE { n } else { HB_SIZE };
    #[cfg(not(feature = "s390-dfltcc-deflate"))]
    return n;
}

/* ===========================================================================
 * Allocate a big buffer and divide it up into the various buffers deflate needs.
 * Handles alignment of allocated buffer and alignment of individual buffers.
 */
/// # Safety
///
/// `strm` must be valid, and its zalloc must hand out memory that it may use.
unsafe fn alloc_deflate(
    strm: *mut z_stream,
    window_bits: c_int,
    lit_bufsize: c_int,
) -> *mut deflate_allocs {
    let mut curr_size = 0;

    /* Define sizes */
    let window_size = deflate_adjust_window_size((1 << window_bits) * 2);
    let prev_size = (1 << window_bits) * size_of::<Pos>();
    let head_size = HASH_SIZE * size_of::<Pos>();
    let pending_size = pending_buf_bytes(lit_bufsize as usize);
    let state_size = DEFLATE_STATE_SIZE;
    let alloc_size = size_of::<deflate_allocs>();

    /* Calculate relative buffer positions and paddings */
    let window_pos = pad_window(curr_size);
    curr_size = window_pos + window_size;

    let prev_pos = pad_64(curr_size);
    curr_size = prev_pos + prev_size;

    let head_pos = pad_64(curr_size);
    curr_size = head_pos + head_size;

    let pending_pos = pad_64(curr_size);
    curr_size = pending_pos + pending_size;

    let state_pos = pad_64(curr_size);
    curr_size = state_pos + state_size;

    let alloc_pos = pad_16(curr_size);
    curr_size = alloc_pos + alloc_size;

    /* Add 64-1 or 4096-1 to allow window alignment, and round size of buffer up to multiple of 64 */
    let total_size = pad_64(curr_size + (WINDOW_PAD_SIZE - 1));

    // SAFETY: the caller guarantees the stream and its allocator are valid. Every buffer below
    // lies inside the total_size bytes that the allocator handed out.
    unsafe {
        /* Allocate buffer, align to 64-byte cacheline, and zerofill the resulting buffer */
        let Some(zalloc) = (*strm).zalloc else {
            return ptr::null_mut();
        };
        let original_buf = zalloc((*strm).opaque, 1, total_size as c_uint).cast::<u8>();
        if original_buf.is_null() {
            return ptr::null_mut();
        }

        let buff = original_buf.add(padsz(original_buf.addr(), WINDOW_PAD_SIZE));

        /* Initialize alloc_bufs */
        let alloc_bufs = buff.add(alloc_pos).cast::<deflate_allocs>();
        (*alloc_bufs).buf_start = original_buf;
        (*alloc_bufs).zfree = (*strm).zfree;

        /* Assign buffers */
        (*alloc_bufs).window = buff.add(window_pos);
        (*alloc_bufs).prev = buff.add(prev_pos).cast::<Pos>();
        (*alloc_bufs).head = buff.add(head_pos).cast::<Pos>();
        (*alloc_bufs).pending_buf = buff.add(pending_pos);
        (*alloc_bufs).state = buff.add(state_pos).cast::<deflate_state>();

        ptr::write_bytes((*alloc_bufs).prev.cast::<u8>(), 0, prev_size);

        alloc_bufs
    }
}

/* ===========================================================================
 * Free all allocated deflate buffers
 */
/// # Safety
///
/// `strm` must be a valid deflate stream.
#[inline]
unsafe fn free_deflate(strm: *mut z_stream) {
    // SAFETY: the caller guarantees the stream and its state are valid.
    unsafe {
        let state = (*strm).state.cast::<deflate_state>();

        if !(*state).alloc_bufs.is_null() {
            let alloc_bufs = (*state).alloc_bufs;
            if let Some(zfree) = (*alloc_bufs).zfree {
                zfree((*strm).opaque, (*alloc_bufs).buf_start.cast::<c_void>());
            }
            (*strm).state = ptr::null_mut();
        }
    }
}

/* ===========================================================================
 * Initialize deflate state and buffers.
 * This function is hidden in ZLIB_COMPAT builds.
 */
/// # Safety
///
/// `strm` must be null or valid for reads and writes, with zalloc, zfree and opaque set up or
/// null.
#[cfg_attr(not(feature = "zlib-compat"), unsafe(export_name = "zng_deflateInit2"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateInit2(
    strm: *mut z_stream,
    mut level: i32,
    method: i32,
    mut windowBits: i32,
    memLevel: i32,
    strategy: i32,
) -> i32 {
    /* Todo: ignore strm->next_in if we use it as window */
    let mut wrap = 1;

    /* Initialize functable */
    if functable::force_init_failed() {
        return Z_VERSION_ERROR;
    }

    if strm.is_null() {
        return Z_STREAM_ERROR;
    }

    // SAFETY: the caller guarantees a stream that is not null is valid. The state and its buffers
    // come from alloc_deflate.
    unsafe {
        (*strm).msg = ptr::null();
        if (*strm).zalloc.is_none() {
            (*strm).zalloc = Some(zcalloc);
            (*strm).opaque = ptr::null_mut();
        }
        if (*strm).zfree.is_none() {
            (*strm).zfree = Some(zcfree);
        }

        if level == Z_DEFAULT_COMPRESSION {
            level = 6;
        }

        if windowBits < 0 {
            /* suppress zlib wrapper */
            wrap = 0;
            if windowBits < -MAX_WBITS {
                return Z_STREAM_ERROR;
            }
            windowBits = -windowBits;
        } else if windowBits > MAX_WBITS {
            wrap = 2; /* write gzip wrapper instead */
            windowBits -= 16;
        }
        if !(1..=MAX_MEM_LEVEL).contains(&memLevel)
            || method != Z_DEFLATED
            || !(MIN_WBITS..=MAX_WBITS).contains(&windowBits)
            || !(0..=9).contains(&level)
            || !(0..=Z_FIXED).contains(&strategy)
            || (windowBits == 8 && wrap != 1)
        {
            return Z_STREAM_ERROR;
        }
        if windowBits == 8 {
            windowBits = 9; /* until 256-byte window bug fixed */
        }

        /* Allocate buffers */
        let lit_bufsize = 1 << (memLevel + 6);
        let alloc_bufs = alloc_deflate(strm, windowBits, lit_bufsize);
        if alloc_bufs.is_null() {
            return Z_MEM_ERROR;
        }

        let s = (*alloc_bufs).state;
        (*s).alloc_bufs = alloc_bufs;
        (*s).window = (*alloc_bufs).window;
        (*s).prev = (*alloc_bufs).prev;
        (*s).head = (*alloc_bufs).head;
        (*s).pending_buf = (*alloc_bufs).pending_buf;

        (*strm).state = s.cast::<internal_state>();
        (*s).strm = strm;
        (*s).status = INIT_STATE; /* to pass state test in deflateReset() */

        (*s).wrap = wrap;
        (*s).w_size = 1 << windowBits;

        (*s).high_water = 0; /* nothing written to s->window yet */

        (*s).lit_bufsize = lit_bufsize as c_uint; /* 16K elements by default */

        /* We overlay pending_buf and sym_buf. This works since the average size
         * for length/distance pairs over any compressed block is assured to be 31
         * bits or less.
         *
         * Analysis: The longest fixed codes are a length code of 8 bits plus 5
         * extra bits, for lengths 131 to 257. The longest fixed distance codes are
         * 5 bits plus 13 extra bits, for distances 16385 to 32768. The longest
         * possible fixed-codes length/distance pair is then 31 bits total.
         *
         * sym_buf starts one-fourth of the way into pending_buf. So there are
         * three bytes in sym_buf for every four bytes in pending_buf. Each symbol
         * in sym_buf is three bytes -- two for the distance and one for the
         * literal/length. As each symbol is consumed, the pointer to the next
         * sym_buf value to read moves forward three bytes. From that symbol, up to
         * 31 bits are written to pending_buf. The closest the written pending_buf
         * bits gets to the next sym_buf symbol to read is just before the last
         * code is written. At that time, 31*(n-2) bits have been written, just
         * after 24*(n-2) bits have been consumed from sym_buf. sym_buf starts at
         * 8*n bits into pending_buf. (Note that the symbol buffer fills when n-1
         * symbols are written.) The closest the writing gets to what is unread is
         * then n+14 bits. Here n is lit_bufsize, which is 16384 by default, and
         * can range from 128 to 32768.
         *
         * Therefore, at a minimum, there are 142 bits of space between what is
         * written and what is read in the overlain buffers, so the symbols cannot
         * be overwritten by the compressed data. That space is actually 139 bits,
         * due to the three-bit fixed-code block header.
         *
         * That covers the case where either Z_FIXED is specified, forcing fixed
         * codes, or when the use of fixed codes is chosen, because that choice
         * results in a smaller compressed block than dynamic codes. That latter
         * condition then assures that the above analysis also covers all dynamic
         * blocks. A dynamic-code block will only be chosen to be emitted if it has
         * fewer bits than a fixed-code block would for the same set of symbols.
         * Therefore its average symbol length is assured to be less than 31. So
         * the compressed data for a dynamic block also cannot overwrite the
         * symbols from which it is being constructed.
         */

        (*s).pending_buf_size = (*s).lit_bufsize * 4;

        set_symbol_buffers(s);
        #[cfg(feature = "lit-mem")]
        {
            (*s).sym_end = (*s).lit_bufsize - 1;
        }
        #[cfg(not(feature = "lit-mem"))]
        {
            (*s).sym_end = ((*s).lit_bufsize - 1) * 3;
        }
        /* We avoid equality with lit_bufsize*3 because of wraparound at 64K
         * on 16 bit machines and because stored blocks are restricted to
         * 64K-1 bytes.
         */

        (*s).level = level;
        (*s).strategy = strategy;
        (*s).block_open = 0;
        (*s).reproducible = 0;

        deflateReset(strm)
    }
}

/// Points the symbol buffers into the pending buffer.
///
/// # Safety
///
/// `s` must point to a deflate_state whose pending_buf and lit_bufsize are set.
#[inline]
unsafe fn set_symbol_buffers(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the pending buffer is valid. It holds LIT_BUFS times
    // lit_bufsize bytes plus the padding.
    unsafe {
        #[cfg(feature = "lit-mem")]
        {
            (*s).d_buf = (*s)
                .pending_buf
                .add((((*s).lit_bufsize as usize) << 1) + PENDING_BUF_PAD)
                .cast::<u16>();
            (*s).l_buf = (*s)
                .pending_buf
                .add((((*s).lit_bufsize as usize) << 2) + PENDING_BUF_PAD);
        }
        #[cfg(not(feature = "lit-mem"))]
        {
            (*s).sym_buf = (*s)
                .pending_buf
                .add((*s).lit_bufsize as usize + PENDING_BUF_PAD);
        }
    }
}

/// # Safety
///
/// `strm` must be null or valid for reads and writes, with zalloc, zfree and opaque set up or
/// null.
#[cfg(not(feature = "zlib-compat"))]
#[unsafe(export_name = "zng_deflateInit")]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateInit(strm: *mut z_stream, level: i32) -> i32 {
    // SAFETY: the caller upholds the contract of deflateInit2.
    unsafe {
        deflateInit2(
            strm,
            level,
            Z_DEFLATED,
            MAX_WBITS,
            DEF_MEM_LEVEL,
            Z_DEFAULT_STRATEGY,
        )
    }
}

/// deflateInit is a macro in zlib.h to allow checking the zlib version
/// and the compiler's view of z_stream
///
/// # Safety
///
/// `strm` must be null or valid for reads and writes, with zalloc, zfree and opaque set up or
/// null.
#[cfg(feature = "zlib-compat")]
#[allow(non_snake_case)]
#[inline]
pub(crate) unsafe fn deflateInit(strm: *mut z_stream, level: i32) -> i32 {
    // SAFETY: the caller upholds the contract of deflateInit_, and the version is a NUL
    // terminated string.
    unsafe {
        deflateInit_(
            strm,
            level,
            ZLIB_VERSION.as_ptr(),
            size_of::<z_stream>() as i32,
        )
    }
}

/* Function used by zlib.h and zlib-ng version 2.0 macros */
/// # Safety
///
/// `strm` must be null or valid for reads and writes, and `version` must be null or point to a
/// string.
#[unsafe(export_name = prefix!("deflateInit_"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateInit_(
    strm: *mut z_stream,
    level: i32,
    version: *const c_char,
    stream_size: i32,
) -> i32 {
    // SAFETY: the caller upholds the contracts of check_ver_stsize and deflateInit2.
    unsafe {
        if check_ver_stsize(version, stream_size) {
            return Z_VERSION_ERROR;
        }
        deflateInit2(
            strm,
            level,
            Z_DEFLATED,
            MAX_WBITS,
            DEF_MEM_LEVEL,
            Z_DEFAULT_STRATEGY,
        )
    }
}

/* Function used by zlib.h and zlib-ng version 2.0 macros */
/// # Safety
///
/// `strm` must be null or valid for reads and writes, and `version` must be null or point to a
/// string.
#[unsafe(export_name = prefix!("deflateInit2_"))]
#[allow(non_snake_case, clippy::too_many_arguments)]
pub unsafe extern "C" fn deflateInit2_(
    strm: *mut z_stream,
    level: i32,
    method: i32,
    windowBits: i32,
    memLevel: i32,
    strategy: i32,
    version: *const c_char,
    stream_size: i32,
) -> i32 {
    // SAFETY: the caller upholds the contracts of check_ver_stsize and deflateInit2.
    unsafe {
        if check_ver_stsize(version, stream_size) {
            return Z_VERSION_ERROR;
        }
        deflateInit2(strm, level, method, windowBits, memLevel, strategy)
    }
}

/* =========================================================================
 * Check for a valid deflate stream state. Return 0 if ok, 1 if not.
 */
/// # Safety
///
/// `strm` must be null or valid for reads, and its state must be null or a deflate state.
#[allow(non_snake_case)]
unsafe fn deflateStateCheck(strm: *mut z_stream) -> bool {
    // SAFETY: the caller guarantees a stream that is not null is readable, and a state that is
    // not null is a deflate state.
    unsafe {
        if strm.is_null() || (*strm).zalloc.is_none() || (*strm).zfree.is_none() {
            return true;
        }
        let s = (*strm).state.cast::<deflate_state>();
        s.is_null()
            || (*s).alloc_bufs.is_null()
            || (*s).strm != strm
            || ((*s).status < INIT_STATE || (*s).status > MAX_STATE)
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up, and `dictionary` must be null or
/// valid for reads of `dictLength` bytes.
#[unsafe(export_name = prefix!("deflateSetDictionary"))]
#[allow(non_snake_case, clippy::unnecessary_cast, clippy::useless_conversion)]
pub unsafe extern "C" fn deflateSetDictionary(
    strm: *mut z_stream,
    mut dictionary: *const u8,
    mut dictLength: u32,
) -> i32 {
    // SAFETY: the caller guarantees the stream and the dictionary. deflateStateCheck vouches for
    // the state, and fill_window keeps strstart and lookahead inside the window.
    unsafe {
        if deflateStateCheck(strm) || dictionary.is_null() {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state.cast::<deflate_state>();
        let wrap = (*s).wrap;
        if wrap == 2 || (wrap == 1 && (*s).status != INIT_STATE) || (*s).lookahead != 0 {
            return Z_STREAM_ERROR;
        }

        let insert_batch = insert_batch_fn(s);

        /* when using zlib wrappers, compute Adler-32 for provided dictionary */
        if wrap == 1 {
            (*strm).adler = z_checksum_t::from(functable::adler32(
                (*strm).adler as u32,
                dictionary,
                dictLength as usize,
            ));
        }
        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-deflate")]
        if dfltcc_deflate::dfltcc_can_deflate(strm) != 0 {
            return dfltcc_deflate::dfltcc_deflate_set_dictionary(strm, dictionary, dictLength);
        }
        (*s).wrap = 0; /* avoid computing Adler-32 in read_buf */

        let hashless = hashless((*s).level, (*s).strategy);

        /* if dictionary would fill window, just replace the history */
        if dictLength >= (*s).w_size {
            if wrap == 0 {
                /* already empty otherwise */
                if !hashless {
                    clear_hash(s);
                }
                (*s).strstart = 0;
                (*s).block_start = 0;
                (*s).insert = 0;
            }
            dictionary = dictionary.add((dictLength - (*s).w_size) as usize); /* use the tail */
            dictLength = (*s).w_size;
        }

        /* insert dictionary into window and hash */
        let avail = (*strm).avail_in;
        let next = (*strm).next_in;
        (*strm).avail_in = dictLength;
        (*strm).next_in = dictionary;
        fill_window(s);
        while (*s).lookahead >= MIN_MATCH {
            let str = (*s).strstart;
            let n = (*s).lookahead - (MIN_MATCH - 1);
            if !hashless {
                insert_batch(s, (*s).window, str, n);
            }
            (*s).strstart = str + n;
            (*s).lookahead = MIN_MATCH - 1;
            fill_window(s);
        }
        (*s).strstart += (*s).lookahead;
        (*s).block_start = (*s).strstart as c_int;
        (*s).insert = (*s).lookahead;
        (*s).lookahead = 0;
        (*s).prev_length = 0;
        (*s).match_available = 0;
        (*strm).next_in = next;
        (*strm).avail_in = avail;
        (*s).wrap = wrap;
        Z_OK
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up. `dictionary` must be null or valid
/// for writes of the window size, and `dictLength` must be null or valid for writes.
#[unsafe(export_name = prefix!("deflateGetDictionary"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateGetDictionary(
    strm: *mut z_stream,
    dictionary: *mut u8,
    dictLength: *mut u32,
) -> i32 {
    // SAFETY: the caller guarantees the stream and both outputs. deflateStateCheck vouches for
    // the state, whose window holds strstart + lookahead bytes.
    unsafe {
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-deflate")]
        if dfltcc_deflate::dfltcc_can_deflate(strm) != 0 {
            return dfltcc_deflate::dfltcc_deflate_get_dictionary(strm, dictionary, dictLength);
        }
        let s = (*strm).state.cast::<deflate_state>();
        let mut len = (*s).strstart + (*s).lookahead;
        if len > (*s).w_size {
            len = (*s).w_size;
        }
        if !dictionary.is_null() && len != 0 {
            ptr::copy_nonoverlapping(
                (*s).window
                    .add(((*s).strstart + (*s).lookahead - len) as usize),
                dictionary,
                len as usize,
            );
        }
        if !dictLength.is_null() {
            *dictLength = len;
        }
        Z_OK
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up.
#[unsafe(export_name = prefix!("deflateResetKeep"))]
#[allow(non_snake_case, clippy::useless_conversion)]
pub unsafe extern "C" fn deflateResetKeep(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees the stream, and deflateStateCheck vouches for the state.
    unsafe {
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }

        (*strm).total_out = 0;
        (*strm).total_in = 0;
        (*strm).msg = ptr::null(); /* use zfree if we ever allocate msg dynamically */
        (*strm).data_type = Z_UNKNOWN;

        let s = (*strm).state.cast::<deflate_state>();
        (*s).pending = 0;
        (*s).pending_out = (*s).pending_buf;

        if (*s).wrap < 0 {
            (*s).wrap = -(*s).wrap; /* was made negative by deflate(..., Z_FINISH); */
        }

        (*s).status = if (*s).wrap == 2 {
            GZIP_STATE
        } else {
            INIT_STATE
        };

        if (*s).wrap == 2 {
            (*strm).adler = z_checksum_t::from(CRC32_INITIAL_VALUE);
        } else {
            (*strm).adler = z_checksum_t::from(ADLER32_INITIAL_VALUE);
        }
        (*s).last_flush = -2;

        (*s).gzhead = ptr::null_mut(); /* reset the gzip header */

        zng_tr_init(s);

        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-deflate")]
        dfltcc_deflate::dfltcc_reset_deflate_state(strm);

        Z_OK
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up.
#[unsafe(export_name = prefix!("deflateReset"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateReset(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller upholds the contract of deflateResetKeep, which vouches for the state.
    unsafe {
        let ret = deflateResetKeep(strm);
        if ret == Z_OK {
            lm_init((*strm).state.cast::<deflate_state>());
        }
        ret
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up. `head` must stay valid for as long
/// as the stream writes the header.
#[unsafe(export_name = prefix!("deflateSetHeader"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateSetHeader(strm: *mut z_stream, head: *mut gz_header) -> i32 {
    // SAFETY: the caller guarantees the stream, and deflateStateCheck vouches for the state.
    unsafe {
        if deflateStateCheck(strm) || (*(*strm).state.cast::<deflate_state>()).wrap != 2 {
            return Z_STREAM_ERROR;
        }
        (*(*strm).state.cast::<deflate_state>()).gzhead = head;
        Z_OK
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up. `pending` and `bits` must be null
/// or valid for writes.
#[unsafe(export_name = prefix!("deflatePending"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflatePending(
    strm: *mut z_stream,
    pending: *mut u32,
    bits: *mut i32,
) -> i32 {
    // SAFETY: the caller guarantees the stream and both outputs, and deflateStateCheck vouches
    // for the state.
    unsafe {
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state.cast::<deflate_state>();
        if !pending.is_null() {
            *pending = (*s).pending;
        }
        if !bits.is_null() {
            *bits = (*s).bi_valid;
        }
        Z_OK
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up. `bits` must be null or valid for
/// writes.
#[unsafe(export_name = prefix!("deflateUsed"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateUsed(strm: *mut z_stream, bits: *mut i32) -> i32 {
    // SAFETY: the caller guarantees the stream and the output, and deflateStateCheck vouches
    // for the state.
    unsafe {
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        if !bits.is_null() {
            *bits = (*(*strm).state.cast::<deflate_state>()).bi_used;
        }
        Z_OK
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up.
#[unsafe(export_name = prefix!("deflatePrime"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflatePrime(strm: *mut z_stream, mut bits: i32, value: i32) -> i32 {
    let mut value64 = value as u64;
    const BUF_BITS: i32 = BIT_BUF_SIZE as i32;

    // SAFETY: the caller guarantees the stream, and deflateStateCheck vouches for the state. The
    // check below keeps room in the pending buffer for the bits.
    unsafe {
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state.cast::<deflate_state>();

        let room = (*s)
            .pending_out
            .wrapping_add(((BIT_BUF_SIZE + 7) >> 3) as usize);
        #[cfg(feature = "lit-mem")]
        if !(0..=BUF_BITS).contains(&bits) || (*s).d_buf.cast::<u8>() < room {
            return Z_BUF_ERROR;
        }
        #[cfg(not(feature = "lit-mem"))]
        if !(0..=BUF_BITS).contains(&bits)
            || bits > (size_of::<i32>() << 3) as i32
            || (*s).sym_buf < room
        {
            return Z_BUF_ERROR;
        }

        loop {
            let put = (BUF_BITS - (*s).bi_valid).min(bits);

            if (*s).bi_valid == 0 {
                (*s).bi_buf = value64;
            } else {
                (*s).bi_buf |= (value64 & ((1u64 << put) - 1)) << (*s).bi_valid;
            }
            (*s).bi_valid += put;
            zng_tr_flush_bits(s);
            // A shift by all 64 bits leaves nothing, which C leaves undefined.
            value64 = value64.checked_shr(put as u32).unwrap_or(0);
            bits -= put;
            if bits == 0 {
                break;
            }
        }
        Z_OK
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up, with valid buffers behind next_in
/// and next_out.
#[unsafe(export_name = prefix!("deflateParams"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateParams(strm: *mut z_stream, mut level: i32, strategy: i32) -> i32 {
    #[cfg_attr(not(feature = "s390-dfltcc-deflate"), allow(unused_mut))]
    let mut hook_flush = Z_NO_FLUSH;

    // SAFETY: the caller guarantees the stream and its buffers, and deflateStateCheck vouches
    // for the state. Both levels are checked to be inside the configuration table.
    unsafe {
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state.cast::<deflate_state>();

        if level == Z_DEFAULT_COMPRESSION {
            level = 6;
        }
        if !(0..=9).contains(&level) || !(0..=Z_FIXED).contains(&strategy) {
            return Z_STREAM_ERROR;
        }
        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-deflate")]
        if dfltcc_deflate::dfltcc_deflate_params(strm, level, strategy, &mut hook_flush)
            == Z_STREAM_ERROR
        {
            return Z_STREAM_ERROR;
        }
        let func = configuration((*s).level).func;

        if ((strategy != (*s).strategy || !ptr::fn_addr_eq(func, configuration(level).func))
            && (*s).last_flush != -2)
            || hook_flush != Z_NO_FLUSH
        {
            /* Flush the last buffer. Use Z_BLOCK mode, unless the hook requests a "stronger" one. */
            let flush = if rank(hook_flush) > rank(Z_BLOCK) {
                hook_flush
            } else {
                Z_BLOCK
            };
            let err = deflate(strm, flush);
            if err == Z_STREAM_ERROR {
                return err;
            }
            if (*strm).avail_in != 0
                || (((*s).strstart as c_int - (*s).block_start) as c_uint)
                    .wrapping_add((*s).lookahead)
                    != 0
                || !deflate_done(strm, flush)
            {
                return Z_BUF_ERROR;
            }
        }

        let hashless_now = hashless(level, strategy);
        let was_hashless = hashless((*s).level, (*s).strategy);

        /* Stale if the hash usage flipped (to/from huffman/rle/stored), the hash
         * function changed at MIN_ROLL_LEVEL, or quick at level 1 left prev unmaintained. */
        let stale_chain = (hashless_now != was_hashless)
            || (level >= MIN_ROLL_LEVEL) != ((*s).level >= MIN_ROLL_LEVEL)
            || (HAVE_QUICK_STRATEGY && (*s).level == 1 && level != 1);

        /* Rebuild the hash chains when fill_window is called. */
        if stale_chain && !hashless_now {
            clear_hash(s);
            (*s).ins_h = 0;
            (*s).insert = (*s).strstart.min((*s).w_size);
        }

        if (*s).level != level {
            lm_set_level(s, level);
        }
        (*s).strategy = strategy;
        Z_OK
    }
}

/// Returns whether the last deflate(flush) operation did everything it's supposed to do.
///
/// # Safety
///
/// `strm` must be a valid deflate stream.
#[inline(always)]
unsafe fn deflate_done(_strm: *mut z_stream, _flush: c_int) -> bool {
    // SAFETY: the caller guarantees the stream is valid.
    #[cfg(feature = "s390-dfltcc-deflate")]
    return unsafe { dfltcc_deflate::dfltcc_deflate_done(_strm, _flush) != 0 };
    #[cfg(not(feature = "s390-dfltcc-deflate"))]
    return true;
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up.
#[unsafe(export_name = prefix!("deflateTune"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateTune(
    strm: *mut z_stream,
    good_length: i32,
    max_lazy: i32,
    nice_length: i32,
    max_chain: i32,
) -> i32 {
    // SAFETY: the caller guarantees the stream, and deflateStateCheck vouches for the state.
    unsafe {
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state.cast::<deflate_state>();
        (*s).good_match = good_length as c_uint;
        (*s).max_lazy_match = max_lazy as c_uint;
        (*s).nice_match = nice_length;
        (*s).max_chain_length = max_chain as c_uint;
        Z_OK
    }
}

/* =========================================================================
 * For the default windowBits of 15 and memLevel of 8, this function returns
 * a close to exact, as well as small, upper bound on the compressed size.
 * They are coded as constants here for a reason--if the #define's are
 * changed, then this function needs to be changed as well.  The return
 * value for 15 and 8 only works for those exact settings.
 *
 * For any setting other than those defaults for windowBits and memLevel,
 * the value returned is a conservative worst case for the maximum expansion
 * resulting from using fixed blocks instead of stored blocks, which deflate
 * can emit on compressed data for some combinations of the parameters.
 *
 * This function could be more sophisticated to provide closer upper bounds for
 * every combination of windowBits and memLevel.  But even the conservative
 * upper bound of about 14% expansion does not seem onerous for output buffer
 * allocation.
 */
/// # Safety
///
/// `strm` must be null or valid for reads, with a state that is null or a deflate state.
#[unsafe(export_name = prefix!("deflateBound_z"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateBound_z(strm: *mut z_stream, sourceLen: usize) -> usize {
    // SAFETY: the caller guarantees the stream, and deflateStateCheck vouches for the state. A
    // gzip header that the application set stays valid while the stream uses it.
    unsafe {
        /* conservative upper bound for compressed data */
        #[cfg_attr(not(feature = "s390-dfltcc-deflate"), allow(unused_mut))]
        let mut complen = sourceLen
            .wrapping_add(sourceLen.wrapping_add(7) >> 3)
            .wrapping_add(sourceLen.wrapping_add(63) >> 6)
            .wrapping_add(5);
        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-deflate")]
        if deflateStateCheck(strm) || dfltcc_deflate::dfltcc_can_deflate(strm) != 0 {
            complen = crate::arch::s390::dfltcc_common::deflate_bound_complen(sourceLen);
        }

        /* if can't get parameters, return conservative bound plus a wrapper */
        if deflateStateCheck(strm) {
            let bound = complen.wrapping_add(GZIP_WRAPLEN);
            return if bound < sourceLen { usize::MAX } else { bound };
        }

        /* compute wrapper length */
        let s = (*strm).state.cast::<deflate_state>();
        let wraplen = match (*s).wrap.wrapping_abs() {
            /* raw deflate */
            0 => 0,
            /* zlib wrapper */
            1 => ZLIB_WRAPLEN + if (*s).strstart != 0 { 4 } else { 0 },
            /* gzip wrapper */
            2 => {
                let mut wraplen = GZIP_WRAPLEN;
                let gzhead = (*s).gzhead;
                if !gzhead.is_null() {
                    /* user-supplied gzip header */
                    if !(*gzhead).extra.is_null() {
                        wraplen = wraplen.wrapping_add(2 + (*gzhead).extra_len as usize);
                    }
                    let mut str = (*gzhead).name;
                    if !str.is_null() {
                        loop {
                            wraplen = wraplen.wrapping_add(1);
                            let byte = *str;
                            str = str.add(1);
                            if byte == 0 {
                                break;
                            }
                        }
                    }
                    str = (*gzhead).comment;
                    if !str.is_null() {
                        loop {
                            wraplen = wraplen.wrapping_add(1);
                            let byte = *str;
                            str = str.add(1);
                            if byte == 0 {
                                break;
                            }
                        }
                    }
                    if (*gzhead).hcrc != 0 {
                        wraplen = wraplen.wrapping_add(2);
                    }
                }
                wraplen
            }
            /* for compiler happiness */
            _ => ZLIB_WRAPLEN,
        };

        /* if not default parameters, return conservative bound */
        /* hook for IBM Z DFLTCC */
        #[cfg(feature = "s390-dfltcc-deflate")]
        let need_conservative_bound = dfltcc_deflate::dfltcc_can_deflate(strm) != 0;
        #[cfg(not(feature = "s390-dfltcc-deflate"))]
        let need_conservative_bound = false;
        if need_conservative_bound || w_bits(s) != MAX_WBITS as u32 || HASH_BITS < 15 {
            if (*s).level == 0 {
                /* upper bound for stored blocks with length 127 (memLevel == 1) --
                ~4% overhead plus a small constant */
                complen = sourceLen
                    .wrapping_add(sourceLen >> 5)
                    .wrapping_add(sourceLen >> 7)
                    .wrapping_add(sourceLen >> 11)
                    .wrapping_add(7);
            }

            let bound = complen.wrapping_add(wraplen);
            return if bound < sourceLen { usize::MAX } else { bound };
        }

        #[cfg(not(feature = "no-quick-strategy"))]
        let bound = sourceLen /* The source size itself */
            .wrapping_add(usize::from(sourceLen == 0)) /* Always at least one byte for any input */
            .wrapping_add(usize::from(sourceLen < 9)) /* One extra byte for lengths less than 9 */
            .wrapping_add(deflate_quick_overhead(sourceLen)) /* Source encoding overhead, padded to next full byte */
            .wrapping_add(DEFLATE_BLOCK_OVERHEAD) /* Deflate block overhead bytes */
            .wrapping_add(wraplen); /* none, zlib or gzip wrapper */
        #[cfg(feature = "no-quick-strategy")]
        let bound = sourceLen
            .wrapping_add(sourceLen >> 4)
            .wrapping_add(7)
            .wrapping_add(wraplen);
        if bound < sourceLen { usize::MAX } else { bound }
    }
}

/// # Safety
///
/// `strm` must be null or valid for reads, with a state that is null or a deflate state.
#[unsafe(export_name = prefix!("deflateBound"))]
#[allow(non_snake_case, clippy::unnecessary_cast)]
pub unsafe extern "C" fn deflateBound(strm: *mut z_stream, sourceLen: c_ulong) -> c_ulong {
    // SAFETY: the caller upholds the contract of deflateBound_z.
    let bound = unsafe { deflateBound_z(strm, sourceLen as usize) };
    c_ulong::try_from(bound).unwrap_or(c_ulong::MAX)
}

/* =========================================================================
 * Flush as much pending output as possible. See flush_pending_inline()
 */
/// # Safety
///
/// `strm` must be a valid deflate stream.
// Kept out of line, as it is across the C source files.
#[inline(never)]
#[unsafe(export_name = prefix!("flush_pending"))]
pub unsafe extern "C" fn flush_pending(strm: *mut z_stream) {
    // SAFETY: the caller guarantees the stream is valid.
    unsafe { flush_pending_inline(strm) };
}

/* ===========================================================================
 * Update the header CRC with the bytes s->pending_buf[beg..s->pending - 1].
 */
/// # Safety
///
/// `s` must point to a deflate_state with a gzip header, and `strm` must be its stream.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
#[inline]
unsafe fn hcrc_update(s: *mut deflate_state, strm: *mut z_stream, beg: u32) {
    // SAFETY: the caller guarantees the state, its header and its stream. The pending buffer
    // holds pending bytes.
    unsafe {
        if (*(*s).gzhead).hcrc != 0 && (*s).pending > beg {
            (*strm).adler = z_checksum_t::from(crc32_small(
                (*strm).adler as u32,
                (*s).pending_buf.add(beg as usize),
                ((*s).pending - beg) as usize,
            ));
        }
    }
}

/// What deflateHeaders tells deflate to do next
enum Headers {
    /// the header is not out yet, hand Z_OK back to the application
    MoreOutput,
    /// the header is out, go on with the data
    Done,
}

/// Flushes the pending buffer and reports whether it is empty. If it is not, the next call of
/// deflate must not fail with Z_BUF_ERROR.
///
/// # Safety
///
/// `s` must point to a deflate_state, and `strm` must be its stream.
#[inline]
unsafe fn flush_header(s: *mut deflate_state, strm: *mut z_stream) -> bool {
    // SAFETY: the caller guarantees the state and its stream.
    unsafe {
        flush_pending(strm);
        if (*s).pending != 0 {
            (*s).last_flush = -1;
            return false;
        }
        true
    }
}

/* =========================================================================
 * Write zlib/gzip header
 */
/// # Safety
///
/// `s` must point to a deflate_state, and `strm` must be its stream. A gzip header that the
/// application set must still be valid.
#[allow(non_snake_case, clippy::unnecessary_cast, clippy::useless_conversion)]
unsafe fn deflateHeaders(s: *mut deflate_state, strm: *mut z_stream) -> Headers {
    // SAFETY: the caller guarantees the state, its stream and its gzip header. The pending
    // buffer is empty when a header starts and every write below checks or knows its room.
    unsafe {
        if (*s).status == INIT_STATE {
            /* zlib header */
            let mut header = ((Z_DEFLATED as c_uint) + ((w_bits(s) - 8) << 4)) << 8;

            let level_flags: c_uint = if (*s).strategy >= Z_HUFFMAN_ONLY || (*s).level < 2 {
                0
            } else if (*s).level < 6 {
                1
            } else if (*s).level == 6 {
                2
            } else {
                3
            };
            header |= level_flags << 6;
            if (*s).strstart != 0 {
                header |= PRESET_DICT;
            }
            header += 31 - (header % 31);

            put_short_msb(s, header as u16);

            /* Save the adler32 of the preset dictionary: */
            if (*s).strstart != 0 {
                put_uint32_msb(s, (*strm).adler as u32);
            }
            (*strm).adler = z_checksum_t::from(ADLER32_INITIAL_VALUE);
            (*s).status = BUSY_STATE;

            /* Compression must start with an empty pending buffer */
            if !flush_header(s, strm) {
                return Headers::MoreOutput;
            }
        }
        if (*s).status == GZIP_STATE {
            /* gzip header */
            (*strm).adler = z_checksum_t::from(CRC32_INITIAL_VALUE);
            put_byte(s, 31);
            put_byte(s, 139);
            put_byte(s, 8);
            let xflags = if (*s).level == 9 {
                2
            } else if (*s).strategy >= Z_HUFFMAN_ONLY || (*s).level < 2 {
                4
            } else {
                0
            };
            let gzhead = (*s).gzhead;
            if gzhead.is_null() {
                put_uint32(s, 0);
                put_byte(s, 0);
                put_byte(s, xflags);
                put_byte(s, OS_CODE);
                (*s).status = BUSY_STATE;

                /* Compression must start with an empty pending buffer */
                if !flush_header(s, strm) {
                    return Headers::MoreOutput;
                }
            } else {
                put_byte(
                    s,
                    u8::from((*gzhead).text != 0)
                        + (if (*gzhead).hcrc != 0 { 2 } else { 0 })
                        + (if (*gzhead).extra.is_null() { 0 } else { 4 })
                        + (if (*gzhead).name.is_null() { 0 } else { 8 })
                        + (if (*gzhead).comment.is_null() { 0 } else { 16 }),
                );
                put_uint32(s, (*gzhead).time as u32);
                put_byte(s, xflags);
                put_byte(s, ((*gzhead).os & 0xff) as u8);
                if !(*gzhead).extra.is_null() {
                    put_short(s, (*gzhead).extra_len as u16);
                }
                if (*gzhead).hcrc != 0 {
                    (*strm).adler = z_checksum_t::from(crc32_small(
                        (*strm).adler as u32,
                        (*s).pending_buf,
                        (*s).pending as usize,
                    ));
                }
                (*s).gzindex = 0;
                (*s).status = EXTRA_STATE;
            }
        }
        if (*s).status == EXTRA_STATE {
            let gzhead = (*s).gzhead;
            if !(*gzhead).extra.is_null() {
                let mut beg = (*s).pending; /* start of bytes to update crc */
                let mut left = ((*gzhead).extra_len & 0xffff) - (*s).gzindex;

                while (*s).pending + left > (*s).pending_buf_size {
                    let copy = (*s).pending_buf_size - (*s).pending;
                    ptr::copy_nonoverlapping(
                        (*gzhead).extra.add((*s).gzindex as usize),
                        (*s).pending_buf.add((*s).pending as usize),
                        copy as usize,
                    );
                    (*s).pending = (*s).pending_buf_size;
                    hcrc_update(s, strm, beg);
                    (*s).gzindex += copy;
                    if !flush_header(s, strm) {
                        return Headers::MoreOutput;
                    }
                    beg = 0;
                    left -= copy;
                }
                ptr::copy_nonoverlapping(
                    (*gzhead).extra.add((*s).gzindex as usize),
                    (*s).pending_buf.add((*s).pending as usize),
                    left as usize,
                );
                (*s).pending += left;
                hcrc_update(s, strm, beg);
                (*s).gzindex = 0;
            }
            (*s).status = NAME_STATE;
        }
        if (*s).status == NAME_STATE {
            let gzhead = (*s).gzhead;
            if !(*gzhead).name.is_null() {
                if !put_header_string(s, strm, (*gzhead).name) {
                    return Headers::MoreOutput;
                }
                (*s).gzindex = 0;
            }
            (*s).status = COMMENT_STATE;
        }
        if (*s).status == COMMENT_STATE {
            let gzhead = (*s).gzhead;
            if !(*gzhead).comment.is_null() && !put_header_string(s, strm, (*gzhead).comment) {
                return Headers::MoreOutput;
            }
            (*s).status = HCRC_STATE;
        }
        if (*s).status == HCRC_STATE {
            if (*(*s).gzhead).hcrc != 0 {
                if (*s).pending + 2 > (*s).pending_buf_size && !flush_header(s, strm) {
                    return Headers::MoreOutput;
                }
                put_short(s, (*strm).adler as u16);
                (*strm).adler = z_checksum_t::from(CRC32_INITIAL_VALUE);
            }
            (*s).status = BUSY_STATE;

            /* Compression must start with an empty pending buffer */
            flush_pending_inline(strm);
            if (*s).pending != 0 {
                (*s).last_flush = -1;
                return Headers::MoreOutput;
            }
        }
        Headers::Done
    }
}

/// Writes the rest of a zero-terminated string of the gzip header, from gzindex on, and updates
/// the header CRC. Returns false when the output is full, with gzindex at the next byte.
///
/// # Safety
///
/// `s` must point to a deflate_state with a gzip header, `strm` must be its stream, and `text`
/// must be a zero-terminated string.
#[inline]
unsafe fn put_header_string(s: *mut deflate_state, strm: *mut z_stream, text: *const u8) -> bool {
    // SAFETY: the caller guarantees the state, its stream and the string. A byte is only written
    // when the pending buffer has room.
    unsafe {
        let mut beg = (*s).pending; /* start of bytes to update crc */

        loop {
            if (*s).pending == (*s).pending_buf_size {
                hcrc_update(s, strm, beg);
                if !flush_header(s, strm) {
                    return false;
                }
                beg = 0;
            }
            let val = *text.add((*s).gzindex as usize);
            (*s).gzindex += 1;
            put_byte(s, val);
            if val == 0 {
                break;
            }
        }
        hcrc_update(s, strm, beg);
        true
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up, with avail_in bytes behind next_in
/// and room for avail_out bytes behind next_out.
#[unsafe(export_name = prefix!("deflate"))]
#[allow(clippy::unnecessary_cast)]
pub unsafe extern "C" fn deflate(strm: *mut z_stream, flush: i32) -> i32 {
    // SAFETY: the caller guarantees the stream and its buffers, and deflateStateCheck vouches
    // for the state. The level is always inside the configuration table.
    unsafe {
        if deflateStateCheck(strm) || !(0..=Z_BLOCK).contains(&flush) {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state.cast::<deflate_state>();

        if (*strm).next_out.is_null()
            || ((*strm).avail_in != 0 && (*strm).next_in.is_null())
            || ((*s).status == FINISH_STATE && flush != Z_FINISH)
        {
            return err_return(strm, Z_STREAM_ERROR);
        }
        if (*strm).avail_out == 0 {
            return err_return(strm, Z_BUF_ERROR);
        }

        let old_flush = (*s).last_flush; /* value of flush param for previous deflate call */
        (*s).last_flush = flush;

        /* Flush as much pending output as possible */
        if (*s).pending != 0 {
            flush_pending_inline(strm);
            if (*strm).avail_out == 0 {
                /* Since avail_out is 0, deflate will be called again with
                 * more output space, but possibly with both pending and
                 * avail_in equal to zero. There won't be anything to do,
                 * but this is not an error situation so make sure we
                 * return OK instead of BUF_ERROR at next call of deflate:
                 */
                (*s).last_flush = -1;
                return Z_OK;
            }

            /* Make sure there is something to do and avoid duplicate consecutive
             * flushes. For repeated and useless calls with Z_FINISH, we keep
             * returning Z_STREAM_END instead of Z_BUF_ERROR.
             */
        } else if (*strm).avail_in == 0 && rank(flush) <= rank(old_flush) && flush != Z_FINISH {
            return err_return(strm, Z_BUF_ERROR);
        }

        /* User must not provide more input after the first FINISH: */
        if (*s).status == FINISH_STATE && (*strm).avail_in != 0 {
            return err_return(strm, Z_BUF_ERROR);
        }

        /* Skip headers if raw deflate stream was requested */
        if (*s).status == INIT_STATE && (*s).wrap == 0 {
            (*s).status = BUSY_STATE;
        }

        if (*s).status != BUSY_STATE && (*s).status != FINISH_STATE && (*s).wrap != 0 {
            /* Write the header */
            if let Headers::MoreOutput = deflateHeaders(s, strm) {
                return Z_OK;
            }
        }

        /* Start a new block or continue the current one. */
        if (*strm).avail_in != 0
            || (*s).lookahead != 0
            || (flush != Z_NO_FLUSH && (*s).status != FINISH_STATE)
        {
            let bstate = match deflate_hook(strm, flush) {
                Some(bstate) => bstate,
                None => {
                    if (*s).level == 0 {
                        deflate_stored(s, flush)
                    } else if (*s).strategy == Z_HUFFMAN_ONLY {
                        deflate_huff(s, flush)
                    } else if (*s).strategy == Z_RLE {
                        deflate_rle(s, flush)
                    } else {
                        (configuration((*s).level).func)(s, flush)
                    }
                }
            };

            if matches!(
                bstate,
                block_state::finish_started | block_state::finish_done
            ) {
                (*s).status = FINISH_STATE;
            }
            if matches!(bstate, block_state::need_more | block_state::finish_started) {
                if (*strm).avail_out == 0 {
                    (*s).last_flush = -1; /* avoid BUF_ERROR next call, see above */
                }
                return Z_OK;
                /* If flush != Z_NO_FLUSH && avail_out == 0, the next call
                 * of deflate should use the same flush parameter to make sure
                 * that the flush is complete. So we don't have to output an
                 * empty block here, this will be done at next call. This also
                 * ensures that for a very small output buffer, we emit at most
                 * one empty block.
                 */
            }
            if matches!(bstate, block_state::block_done) {
                if flush == Z_PARTIAL_FLUSH {
                    zng_tr_align(s);
                } else if flush != Z_BLOCK {
                    /* FULL_FLUSH or SYNC_FLUSH */
                    zng_tr_stored_block(s, ptr::null_mut(), 0, 0);
                    /* For a full flush, this empty block will be recognized
                     * as a special marker by inflate_sync().
                     */
                    if flush == Z_FULL_FLUSH {
                        clear_hash(s); /* forget history */
                        if (*s).lookahead == 0 {
                            (*s).strstart = 0;
                            (*s).block_start = 0;
                            (*s).insert = 0;
                        }
                    }
                }
                flush_pending(strm);
                if (*strm).avail_out == 0 {
                    (*s).last_flush = -1; /* avoid BUF_ERROR at next call, see above */
                    return Z_OK;
                }
            }
        }

        if flush != Z_FINISH {
            return Z_OK;
        }

        /* Write the trailer */
        if (*s).wrap == 2 {
            put_uint32(s, (*strm).adler as u32);
            put_uint32(s, (*strm).total_in as u32);
        } else if (*s).wrap == 1 {
            put_uint32_msb(s, (*strm).adler as u32);
        }
        flush_pending_inline(strm);
        /* If avail_out is zero, the application will call deflate again
         * to flush the rest.
         */
        if (*s).wrap > 0 {
            (*s).wrap = -(*s).wrap; /* write the trailer only once! */
        }
        if (*s).pending == 0 {
            debug_assert!((*s).bi_valid == 0, "bi_buf not flushed");
            return Z_STREAM_END;
        }
        Z_OK
    }
}

/// Invoked for each deflate() call. Useful for plugging arch-specific deflation code. Hands
/// back a block state when that code did the work.
///
/// # Safety
///
/// `strm` must be a valid deflate stream.
#[inline(always)]
unsafe fn deflate_hook(_strm: *mut z_stream, _flush: c_int) -> Option<block_state> {
    #[cfg(feature = "s390-dfltcc-deflate")]
    {
        let mut bstate = block_state::need_more;
        // SAFETY: the caller guarantees the stream is valid.
        if unsafe { dfltcc_deflate::dfltcc_deflate(_strm, _flush, &mut bstate) } != 0 {
            return Some(bstate);
        }
    }
    None
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up.
#[unsafe(export_name = prefix!("deflateEnd"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateEnd(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees the stream, and deflateStateCheck vouches for the state.
    unsafe {
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }

        let status = (*(*strm).state.cast::<deflate_state>()).status;

        /* Free allocated buffers */
        free_deflate(strm);

        if status == BUSY_STATE {
            Z_DATA_ERROR
        } else {
            Z_OK
        }
    }
}

/* =========================================================================
 * Copy the source state to the destination state.
 */
/// # Safety
///
/// `source` must be null or a stream that deflateInit set up, and `dest` must be null or valid
/// for writes.
#[unsafe(export_name = prefix!("deflateCopy"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn deflateCopy(dest: *mut z_stream, source: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees both streams, and deflateStateCheck vouches for the source
    // state. The buffers of the copy come from alloc_deflate with the sizes of the source.
    unsafe {
        if deflateStateCheck(source) || dest.is_null() {
            return Z_STREAM_ERROR;
        }

        let ss = (*source).state.cast::<deflate_state>();

        ptr::copy_nonoverlapping(source, dest, 1);

        let alloc_bufs = alloc_deflate(dest, w_bits(ss) as c_int, (*ss).lit_bufsize as c_int);
        if alloc_bufs.is_null() {
            return Z_MEM_ERROR;
        }

        let ds = (*alloc_bufs).state;

        (*dest).state = ds.cast::<internal_state>();
        ptr::copy_nonoverlapping(ss.cast::<u8>(), ds.cast::<u8>(), DEFLATE_STATE_SIZE);
        (*ds).strm = dest;

        (*ds).alloc_bufs = alloc_bufs;
        (*ds).window = (*alloc_bufs).window;
        (*ds).prev = (*alloc_bufs).prev;
        (*ds).head = (*alloc_bufs).head;
        (*ds).pending_buf = (*alloc_bufs).pending_buf;

        if (*ds).window.is_null()
            || (*ds).prev.is_null()
            || (*ds).head.is_null()
            || (*ds).pending_buf.is_null()
        {
            deflateEnd(dest);
            return Z_MEM_ERROR;
        }

        ptr::copy_nonoverlapping(
            (*ss).window,
            (*ds).window,
            deflate_adjust_window_size((*ds).w_size as usize * 2),
        );
        ptr::copy_nonoverlapping((*ss).prev, (*ds).prev, (*ds).w_size as usize);
        ptr::copy_nonoverlapping((*ss).head, (*ds).head, HASH_SIZE);
        ptr::copy_nonoverlapping(
            (*ss).pending_buf,
            (*ds).pending_buf,
            pending_buf_bytes((*ds).lit_bufsize as usize),
        );

        (*ds).pending_out = (*ds)
            .pending_buf
            .offset((*ss).pending_out.offset_from((*ss).pending_buf));
        set_symbol_buffers(ds);

        (*ds).l_desc.dyn_tree = (&raw mut (*ds).dyn_ltree).cast::<ct_data>();
        (*ds).d_desc.dyn_tree = (&raw mut (*ds).dyn_dtree).cast::<ct_data>();
        (*ds).bl_desc.dyn_tree = (&raw mut (*ds).bl_tree).cast::<ct_data>();

        Z_OK
    }
}

/* ===========================================================================
 * Set longest match variables based on level configuration
 */
/// # Safety
///
/// `s` must point to a deflate_state, and `level` must be from 0 to 9.
unsafe fn lm_set_level(s: *mut deflate_state, level: c_int) {
    // SAFETY: the caller guarantees the state and a level inside the configuration table.
    unsafe {
        let config = configuration(level);
        (*s).max_lazy_match = c_uint::from(config.max_lazy);
        (*s).good_match = c_uint::from(config.good_length);
        (*s).nice_match = c_int::from(config.nice_length);
        (*s).max_chain_length = c_uint::from(config.max_chain);
        if level >= MIN_ROLL_LEVEL {
            set_longest_match(s, functable::longest_match_slow_roll_fptr());
            set_insert_batch(s, insert_roll_batch);
        } else {
            set_longest_match(s, functable::longest_match_slow_knuth_fptr());
            if HAVE_QUICK_STRATEGY && level == 1 {
                set_insert_batch(s, insert_knuth_batch_head);
            } else {
                set_insert_batch(s, insert_knuth_batch);
            }
        }
        (*s).level = level;
    }
}

/* ===========================================================================
 * Initialize the "longest match" routines for a new zlib stream
 */
/// # Safety
///
/// `s` must point to a deflate_state whose level, strategy, w_size and head table are set.
unsafe fn lm_init(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the state and its head table.
    unsafe {
        (*s).window_size = 2 * (*s).w_size;

        if !hashless((*s).level, (*s).strategy) {
            clear_hash(s);
        }

        /* Set the default configuration parameters:
         */
        lm_set_level(s, (*s).level);

        (*s).strstart = 0;
        (*s).block_start = 0;
        (*s).lookahead = 0;
        (*s).insert = 0;
        (*s).prev_length = 0;
        (*s).match_available = 0;
        (*s).match_start = 0;
        (*s).ins_h = 0;
    }
}

/* ===========================================================================
 * Fill the window when the lookahead becomes insufficient.
 * Updates strstart and lookahead.
 *
 * IN assertion: lookahead < MIN_LOOKAHEAD
 * OUT assertions: strstart <= window_size-MIN_LOOKAHEAD
 *    At least one byte has been read, or avail_in == 0; reads are
 *    performed for at least two bytes (required for the zip translate_eol
 *    option -- not supported here).
 */
/// # Safety
///
/// `s` must point to a deflate_state that deflate has set up, with a valid stream behind it.
// Kept out of line, as it is across the C source files.
#[inline(never)]
#[unsafe(export_name = prefix!("fill_window"))]
pub unsafe extern "C" fn fill_window(s: *mut deflate_state) {
    // SAFETY: the caller guarantees the state and its stream. The window holds window_size
    // bytes, and every position below stays inside it.
    unsafe {
        let strm = (*s).strm;
        let insert_batch = insert_batch_fn(s);
        let window = (*s).window;
        let wsize = (*s).w_size;
        let level = (*s).level;

        debug_assert!((*s).lookahead < MIN_LOOKAHEAD, "already enough lookahead");

        loop {
            /* Amount of free space at the end of the window. */
            let mut more = (*s).window_size - (*s).lookahead - (*s).strstart;

            /* If the window is almost full and there is insufficient lookahead,
             * move the upper half to the lower one to make room in the upper half.
             */
            if (*s).strstart >= wsize + max_dist(s) {
                ptr::copy_nonoverlapping(window.add(wsize as usize), window, wsize as usize);
                if (*s).match_start >= wsize {
                    (*s).match_start -= wsize;
                } else {
                    (*s).match_start = 0;
                    (*s).prev_length = 0;
                }
                (*s).strstart -= wsize; /* we now have strstart >= MAX_DIST */
                (*s).block_start -= wsize as c_int;
                if (*s).insert > (*s).strstart {
                    (*s).insert = (*s).strstart;
                }
                if !hashless(level, (*s).strategy) {
                    /* deflate_quick reads the chain head but never walks prev, so it
                     * slides head only. */
                    if HAVE_QUICK_STRATEGY && level == 1 {
                        functable::slide_hash_head(s);
                    } else {
                        functable::slide_hash(s);
                    }
                }
                more += wsize;
            }
            if (*strm).avail_in == 0 {
                break;
            }

            /* If there was no sliding:
             *    strstart <= WSIZE+MAX_DIST-1 && lookahead <= MIN_LOOKAHEAD - 1 &&
             *    more == window_size - lookahead - strstart
             * => more >= window_size - (MIN_LOOKAHEAD-1 + WSIZE + MAX_DIST-1)
             * => more >= window_size - 2*WSIZE + 2
             * In the BIG_MEM or MMAP case (not yet supported),
             *   window_size == input_size + MIN_LOOKAHEAD  &&
             *   strstart + s->lookahead <= input_size => more >= MIN_LOOKAHEAD.
             * Otherwise, window_size == 2*WSIZE so more >= 2.
             * If there was sliding, more >= WSIZE. So in all cases, more >= 2.
             */
            debug_assert!(more >= 2, "more < 2");

            let n = read_buf(
                strm,
                window.add(((*s).strstart + (*s).lookahead) as usize),
                more,
            );
            (*s).lookahead += n;

            /* Initialize the hash value now that we have some input: */
            if !hashless(level, (*s).strategy) && (*s).lookahead + (*s).insert >= MIN_MATCH {
                let str = (*s).strstart - (*s).insert;
                if unlikely(level >= MIN_ROLL_LEVEL) {
                    (*s).ins_h = update_hash_roll(
                        u32::from(*window.add(str as usize)),
                        *window.add(str as usize + 1),
                    );
                } else if str >= 1 {
                    if HAVE_QUICK_STRATEGY && level == 1 {
                        insert_knuth_head(s, window, str + 2 - MIN_MATCH);
                    } else {
                        insert_knuth(s, window, str + 2 - MIN_MATCH);
                    }
                }
                let mut count = (*s).insert;
                if unlikely((*s).lookahead == 1) {
                    count -= 1;
                }
                if count > 0 {
                    insert_batch(s, window, str, count);
                    (*s).insert -= count;
                }
            }
            /* If the whole input has less than STD_MIN_MATCH bytes, ins_h is garbage,
             * but this is not important since only literal bytes will be emitted.
             */
            if !((*s).lookahead < MIN_LOOKAHEAD && (*strm).avail_in != 0) {
                break;
            }
        }

        /* If the WIN_INIT bytes after the end of the current data have never been
         * written, then zero those bytes in order to avoid memory check reports of
         * the use of uninitialized (or uninitialised as Julian writes) bytes by
         * the longest match routines.  Update the high water mark for the next
         * time through here.  WIN_INIT is set to STD_MAX_MATCH since the longest match
         * routines allow scanning to strstart + STD_MAX_MATCH, ignoring lookahead.
         */
        if (*s).high_water < (*s).window_size {
            let curr = (*s).strstart + (*s).lookahead;

            if (*s).high_water < curr {
                /* Previous high water mark below current data -- zero WIN_INIT
                 * bytes or up to end of window, whichever is less.
                 */
                let mut init = (*s).window_size - curr;
                if init > WIN_INIT {
                    init = WIN_INIT;
                }
                ptr::write_bytes(window.add(curr as usize), 0, init as usize);
                (*s).high_water = curr + init;
            } else if (*s).high_water < curr + WIN_INIT {
                /* High water mark at or above current data, but below current data
                 * plus WIN_INIT -- zero out to current data plus WIN_INIT, or up
                 * to end of window, whichever is less.
                 */
                let mut init = curr + WIN_INIT - (*s).high_water;
                if init > (*s).window_size - (*s).high_water {
                    init = (*s).window_size - (*s).high_water;
                }
                ptr::write_bytes(window.add((*s).high_water as usize), 0, init as usize);
                (*s).high_water += init;
            }
        }

        debug_assert!(
            (*s).strstart <= (*s).window_size - MIN_LOOKAHEAD,
            "not enough room for search"
        );
    }
}

/* =========================================================================
 * Checks whether buffer size is sufficient and whether this parameter is a duplicate.
 */
/// # Safety
///
/// `param` must be valid for reads and writes, and `out` must be null or valid the same way.
#[cfg(not(feature = "zlib-compat"))]
#[allow(non_snake_case)]
unsafe fn deflateSetParamPre(
    out: &mut *mut zng_deflate_param_value,
    min_size: usize,
    param: *mut zng_deflate_param_value,
) -> bool {
    // SAFETY: the caller guarantees both parameters.
    unsafe {
        let mut buf_error = (*param).size < min_size;

        if !out.is_null() {
            (**out).status = Z_BUF_ERROR;
            buf_error = true;
        }
        *out = param;
        buf_error
    }
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up. `params` must be valid for reads
/// and writes of `count` values, each with a buffer of its size.
#[cfg(not(feature = "zlib-compat"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_deflateSetParams(
    strm: *mut z_stream,
    params: *mut zng_deflate_param_value,
    count: usize,
) -> i32 {
    let mut new_level: *mut zng_deflate_param_value = ptr::null_mut();
    let mut new_strategy: *mut zng_deflate_param_value = ptr::null_mut();
    let mut new_reproducible: *mut zng_deflate_param_value = ptr::null_mut();
    let mut version_error = false;
    let mut buf_error = false;
    let mut stream_error = false;

    // SAFETY: the caller guarantees the stream and the parameters, and deflateStateCheck vouches
    // for the state. A buffer is only read when its size was checked.
    unsafe {
        /* Initialize the statuses. */
        for i in 0..count {
            (*params.add(i)).status = Z_OK;
        }

        /* Check whether the stream state is consistent. */
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state.cast::<deflate_state>();

        /* Check buffer sizes and detect duplicates. */
        for i in 0..count {
            let param = params.add(i);
            let param_buf_error = match (*param).param {
                Z_DEFLATE_LEVEL => deflateSetParamPre(&mut new_level, size_of::<c_int>(), param),
                Z_DEFLATE_STRATEGY => {
                    deflateSetParamPre(&mut new_strategy, size_of::<c_int>(), param)
                }
                Z_DEFLATE_REPRODUCIBLE => {
                    deflateSetParamPre(&mut new_reproducible, size_of::<c_int>(), param)
                }
                _ => {
                    (*param).status = Z_VERSION_ERROR;
                    version_error = true;
                    false
                }
            };
            if param_buf_error {
                (*param).status = Z_BUF_ERROR;
                buf_error = true;
            }
        }
        /* Exit early if small buffers or duplicates are detected. */
        if buf_error {
            return Z_BUF_ERROR;
        }

        /* Apply changes, remember if there were errors. */
        if !new_level.is_null() || !new_strategy.is_null() {
            let level = if new_level.is_null() {
                (*s).level
            } else {
                (*new_level).buf.cast::<c_int>().read_unaligned()
            };
            let strategy = if new_strategy.is_null() {
                (*s).strategy
            } else {
                (*new_strategy).buf.cast::<c_int>().read_unaligned()
            };
            let ret = deflateParams(strm, level, strategy);
            if ret != Z_OK {
                if !new_level.is_null() {
                    (*new_level).status = Z_STREAM_ERROR;
                }
                if !new_strategy.is_null() {
                    (*new_strategy).status = Z_STREAM_ERROR;
                }
                stream_error = true;
            }
        }
        if !new_reproducible.is_null() {
            let val = (*new_reproducible).buf.cast::<c_int>().read_unaligned();
            if deflate_can_set_reproducible(strm, val) {
                (*s).reproducible = val;
            } else {
                (*new_reproducible).status = Z_STREAM_ERROR;
                stream_error = true;
            }
        }
    }

    /* Report version errors only if there are no real errors. */
    if stream_error {
        Z_STREAM_ERROR
    } else if version_error {
        Z_VERSION_ERROR
    } else {
        Z_OK
    }
}

/// Returns whether reproducibility parameter can be set to a given value.
///
/// # Safety
///
/// `strm` must be a valid deflate stream.
#[cfg(not(feature = "zlib-compat"))]
#[inline(always)]
unsafe fn deflate_can_set_reproducible(_strm: *mut z_stream, _reproducible: c_int) -> bool {
    // SAFETY: the caller guarantees the stream is valid.
    #[cfg(feature = "s390-dfltcc-deflate")]
    return unsafe { dfltcc_deflate::dfltcc_can_set_reproducible(_strm, _reproducible) != 0 };
    #[cfg(not(feature = "s390-dfltcc-deflate"))]
    return true;
}

/* ========================================================================= */
/// # Safety
///
/// `strm` must be null or a stream that deflateInit set up. `params` must be valid for reads
/// and writes of `count` values, each with a buffer of its size.
#[cfg(not(feature = "zlib-compat"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zng_deflateGetParams(
    strm: *mut z_stream,
    params: *mut zng_deflate_param_value,
    count: usize,
) -> i32 {
    let mut buf_error = false;
    let mut version_error = false;

    // SAFETY: the caller guarantees the stream and the parameters, and deflateStateCheck vouches
    // for the state. A buffer is only written when its size was checked.
    unsafe {
        /* Initialize the statuses. */
        for i in 0..count {
            (*params.add(i)).status = Z_OK;
        }

        /* Check whether the stream state is consistent. */
        if deflateStateCheck(strm) {
            return Z_STREAM_ERROR;
        }
        let s = (*strm).state.cast::<deflate_state>();

        for i in 0..count {
            let param = params.add(i);
            let value = match (*param).param {
                Z_DEFLATE_LEVEL => Some((*s).level),
                Z_DEFLATE_STRATEGY => Some((*s).strategy),
                Z_DEFLATE_REPRODUCIBLE => Some((*s).reproducible),
                _ => None,
            };
            match value {
                Some(value) => {
                    if (*param).size < size_of::<c_int>() {
                        (*param).status = Z_BUF_ERROR;
                    } else {
                        (*param).buf.cast::<c_int>().write_unaligned(value);
                    }
                }
                None => {
                    (*param).status = Z_VERSION_ERROR;
                    version_error = true;
                }
            }
            if (*param).status == Z_BUF_ERROR {
                buf_error = true;
            }
        }
    }
    if buf_error {
        Z_BUF_ERROR
    } else if version_error {
        Z_VERSION_ERROR
    } else {
        Z_OK
    }
}
