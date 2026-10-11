//! infback.c -- inflate using a call-back interface
//! Copyright (C) 1995-2026 Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

/*
  This code is largely copied from inflate.c.  Normally either infback.o or
  inflate.o would be linked into an application--not both.  The interface
  with inffast.c is retained so that optimized assembler-coded versions of
  inflate_fast() can be used with either inflate.c or infback.c.
*/
// The width of the bit count differs between targets.
#![allow(clippy::unnecessary_cast, clippy::useless_conversion)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::functable;
use crate::inflate::{
    BAD, DONE, LEN, MATCH, STORED, TABLE, TYPE, alloc_inflate, fixedtables, free_inflate,
    inflate_state,
};
use crate::inflate_p::{
    INFLATE_FAST_MIN_HAVE, INFLATE_FAST_MIN_SAFE, bits_t, chunkcopy_safe, code_bits, code_extra,
    set_bad,
};
use crate::inftrees::{CODES, DISTS, LENS, code, zng_inflate_table};
use crate::zbuild::prefix;
use crate::zconf::{MAX_WBITS, MIN_WBITS};
use crate::zlib::{
    Z_BUF_ERROR, Z_DATA_ERROR, Z_MEM_ERROR, Z_OK, Z_STREAM_END, Z_STREAM_ERROR, Z_VERSION_ERROR,
    in_func, internal_state, out_func, z_stream,
};
use crate::zutil::{MAX_LEN_ROOT_BITS, PKZIP_BUG_WORKAROUND, check_ver_stsize, zcalloc, zcfree};

/*
  strm provides memory allocation functions in zalloc and zfree, or
  NULL to use the library memory allocation functions.

  windowBits is in the range 8..15, and window is a user-supplied
  window and output buffer that is 2**windowBits bytes.

  This function is hidden in ZLIB_COMPAT builds.
*/
/// # Safety
///
/// `strm` must be null or valid for reads and writes, with zalloc, zfree and opaque set up or
/// null. `window` must be null or valid for writes of two to the power of `windowBits` bytes
/// until inflateBackEnd.
#[cfg_attr(
    not(feature = "zlib-compat"),
    unsafe(export_name = "zng_inflateBackInit")
)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateBackInit(
    strm: *mut z_stream,
    windowBits: i32,
    window: *mut u8,
) -> i32 {
    if strm.is_null() || window.is_null() || !(MIN_WBITS..=MAX_WBITS).contains(&windowBits) {
        return Z_STREAM_ERROR;
    }
    // SAFETY: the caller guarantees the stream. The allocation holds the state.
    unsafe {
        (*strm).msg = ptr::null(); /* in case we return an error */
        if (*strm).zalloc.is_none() {
            (*strm).zalloc = Some(zcalloc);
            (*strm).opaque = ptr::null_mut();
        }
        if (*strm).zfree.is_none() {
            (*strm).zfree = Some(zcfree);
        }

        let alloc_bufs = alloc_inflate(strm);
        if alloc_bufs.is_null() {
            return Z_MEM_ERROR;
        }

        let state = (*alloc_bufs).state;
        (*state).alloc_bufs = alloc_bufs;

        (*strm).state = state.cast::<internal_state>();
        (*state).wbits = windowBits as u32;
        (*state).wsize = 1 << windowBits;
        (*state).wbufsize = 1 << windowBits;
        (*state).window = window;
        (*state).wnext = 0;
        (*state).whave = 0;
        #[cfg(feature = "inflate-strict")]
        {
            (*state).dmax = 32768;
        }
        #[cfg(feature = "inflate-allow-invalid-dist")]
        {
            (*state).sane = 1;
        }
        Z_OK
    }
}

/* Function used by zlib.h and zlib-ng version 2.0 macros */
/// # Safety
///
/// `strm` and `window` must uphold the contract of inflateBackInit, and `version` must be null
/// or point to a string.
#[unsafe(export_name = prefix!("inflateBackInit_"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateBackInit_(
    strm: *mut z_stream,
    windowBits: i32,
    window: *mut u8,
    version: *const c_char,
    stream_size: i32,
) -> i32 {
    // SAFETY: the caller upholds the contracts of check_ver_stsize and inflateBackInit.
    unsafe {
        if check_ver_stsize(version, stream_size) {
            return Z_VERSION_ERROR;
        }
        inflateBackInit(strm, windowBits, window)
    }
}

/// C calls a null function pointer when a callback is missing, which stops the program.
#[cold]
fn missing_callback() -> ! {
    unsafe extern "C" {
        fn abort() -> !;
    }
    // SAFETY: abort has no preconditions.
    unsafe { abort() }
}

/*
  strm provides the memory allocation functions and window buffer on input,
  and provides information on the unused input on return.  For Z_DATA_ERROR
  returns, strm will also provide an error message.

  in() and out() are the call-back input and output functions.  When
  inflateBack() needs more input, it calls in().  When inflateBack() has
  filled the window with output, or when it completes with data in the
  window, it calls out() to write out the data.  The application must not
  change the provided input until in() is called again or inflateBack()
  returns.  The application must not change the window/output buffer until
  inflateBack() returns.

  in() and out() are called with a descriptor parameter provided in the
  inflateBack() call.  This parameter can be a structure that provides the
  information required to do the read or write, as well as accumulated
  information on the input and output such as totals and check values.

  in() should return zero on failure.  out() should return non-zero on
  failure.  If either in() or out() fails, than inflateBack() returns a
  Z_BUF_ERROR.  strm->next_in can be checked for NULL to see whether it
  was in() or out() that caused in the error.  Otherwise, inflateBack()
  returns Z_STREAM_END on success, Z_DATA_ERROR for an deflate format
  error, or Z_MEM_ERROR if it could not allocate memory for the state.
  inflateBack() can also return Z_STREAM_ERROR if the input parameters
  are not correct, i.e. strm is NULL or the state was not initialized.
*/
/// # Safety
///
/// `strm` must be null or a stream that inflateBackInit set up, with next_in null or valid for
/// reads of avail_in bytes. `in` must hand out input that stays valid until it is called again,
/// and `out` must accept the window.
#[unsafe(export_name = prefix!("inflateBack"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateBack(
    strm: *mut z_stream,
    r#in: in_func,
    in_desc: *mut c_void,
    out: out_func,
    out_desc: *mut c_void,
) -> i32 {
    /* permutation of code lengths */
    static ORDER: [u16; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    // SAFETY: the caller guarantees the stream, its input and both callbacks. have and left
    // count the bytes that remain at next and put, and no input is read or output written
    // beyond them. The tables hold every entry that an index of lenbits or distbits bits or a
    // table link can reach.
    unsafe {
        /* Check that the strm exists and that the state was initialized */
        if strm.is_null() || (*strm).state.is_null() {
            return Z_STREAM_ERROR;
        }
        let state = (*strm).state.cast::<inflate_state>();

        /* next input */
        let mut next: *const u8;
        /* next output */
        let mut put: *mut u8;
        /* available input and output */
        let mut have: u32;
        let mut left: u32;
        /* bit buffer */
        let mut hold: u64;
        /* bits in bit buffer */
        let mut bits: bits_t;
        /* number of stored or match bytes to copy */
        let mut copy: u32;
        /* where to copy match bytes from */
        let mut from: *const u8;
        /* current decoding table entry */
        let mut here: code;
        /* parent table entry */
        let mut last: code;
        /* length to copy for repeats, bits to drop */
        let mut len: u32;
        /* return code */
        let mut ret: i32;

        /* Reset the state */
        (*strm).msg = ptr::null();
        (*state).mode = TYPE;
        (*state).last = 0;
        (*state).whave = 0;
        next = (*strm).next_in;
        have = if !next.is_null() { (*strm).avail_in } else { 0 };
        hold = 0;
        bits = 0;
        put = (*state).window;
        left = (*state).wsize;

        /* Clear the input bit accumulator */
        macro_rules! initbits {
            () => {
                hold = 0;
                bits = 0;
            };
        }
        /* Return the low n bits of the bit accumulator (n < 16) */
        macro_rules! bits {
            ($n:expr) => {
                (hold as u32) & ((1u32 << ($n)) - 1)
            };
        }
        /* Remove n bits from the bit accumulator */
        macro_rules! dropbits {
            ($n:expr) => {
                let n = $n as u32;
                hold >>= n;
                bits = bits.wrapping_sub(n as bits_t);
            };
        }
        /* Remove zero to seven bits as needed to go to a byte boundary */
        macro_rules! bytebits {
            () => {
                hold >>= bits & 7;
                bits -= bits & 7;
            };
        }
        /* Set mode=BAD and prepare error message */
        macro_rules! bad {
            ($msg:expr) => {
                set_bad(strm, state, $msg)
            };
        }

        /* Inflate until end of block marked as last */
        'machine: loop {
            // These leave the loop, and a macro only sees a label that is in scope where it is
            // defined.
            /* Assure that some input is available.  If input is requested, but denied,
            then return a Z_BUF_ERROR from inflateBack(). */
            macro_rules! pull {
                () => {
                    if have == 0 {
                        let Some(input) = r#in else {
                            missing_callback()
                        };
                        have = input(in_desc, &raw mut next);
                        if have == 0 {
                            next = ptr::null();
                            ret = Z_BUF_ERROR;
                            break 'machine;
                        }
                    }
                };
            }
            /* Get a byte of input into the bit accumulator, or return from inflateBack()
            with an error if there is no input available. */
            macro_rules! pullbyte {
                () => {
                    pull!();
                    have -= 1;
                    hold = hold.wrapping_add(u64::from(*next) << bits);
                    next = next.add(1);
                    bits += 8;
                };
            }
            /* Ensure that there is at least n bits in the bit accumulator.  If there is
            not enough available input to do that, then return from inflate()/inflateBack(). */
            macro_rules! needbits {
                ($n:expr) => {
                    let n = $n as u32;
                    while u32::from(bits) < n {
                        pullbyte!();
                    }
                };
            }
            /* Assure that some output space is available, by writing out the window
            if it's full.  If the write fails, return from inflateBack() with a
            Z_BUF_ERROR. */
            macro_rules! room {
                () => {
                    if left == 0 {
                        put = (*state).window;
                        left = (*state).wsize;
                        (*state).whave = left;
                        let Some(output) = out else {
                            missing_callback()
                        };
                        if output(out_desc, put, left) != 0 {
                            ret = Z_BUF_ERROR;
                            break 'machine;
                        }
                    }
                };
            }

            match (*state).mode {
                TYPE => {
                    /* determine and dispatch block type */
                    if (*state).last != 0 {
                        bytebits!();
                        (*state).mode = DONE;
                        continue;
                    }
                    needbits!(3);
                    (*state).last = bits!(1) as c_int;
                    dropbits!(1);
                    match bits!(2) {
                        0 => {
                            /* stored block */
                            (*state).mode = STORED;
                        }
                        1 => {
                            /* fixed block */
                            fixedtables(state);
                            /* decode codes */
                            (*state).mode = LEN;
                        }
                        2 => {
                            /* dynamic block */
                            (*state).mode = TABLE;
                        }
                        _ => {
                            bad!(c"invalid block type");
                        }
                    }
                    dropbits!(2);
                }

                STORED => {
                    /* get and verify stored block length */
                    /* go to byte boundary */
                    bytebits!();
                    needbits!(32);
                    if (hold & 0xffff) != ((hold >> 16) ^ 0xffff) {
                        bad!(c"invalid stored block lengths");
                        continue;
                    }
                    (*state).length = u32::from(hold as u16);
                    initbits!();

                    /* copy stored block from input to output */
                    while (*state).length != 0 {
                        copy = (*state).length;
                        pull!();
                        room!();
                        copy = copy.min(have);
                        copy = copy.min(left);
                        ptr::copy_nonoverlapping(next, put, copy as usize);
                        have -= copy;
                        next = next.add(copy as usize);
                        left -= copy;
                        put = put.add(copy as usize);
                        (*state).length -= copy;
                    }
                    (*state).mode = TYPE;
                }

                TABLE => {
                    let lens = (&raw mut (*state).lens).cast::<u16>();
                    /* get dynamic table entries descriptor */
                    needbits!(14);
                    (*state).nlen = bits!(5) + 257;
                    dropbits!(5);
                    (*state).ndist = bits!(5) + 1;
                    dropbits!(5);
                    (*state).ncode = bits!(4) + 4;
                    dropbits!(4);
                    if PKZIP_BUG_WORKAROUND == 0 && ((*state).nlen > 286 || (*state).ndist > 30) {
                        bad!(c"too many length or distance symbols");
                        continue;
                    }
                    (*state).have = 0;

                    /* get code length code lengths (not a typo) */
                    while (*state).have < (*state).ncode {
                        needbits!(3);
                        *lens.add(usize::from(*ORDER.get_unchecked((*state).have as usize))) =
                            bits!(3) as u16;
                        (*state).have += 1;
                        dropbits!(3);
                    }
                    while (*state).have < 19 {
                        *lens.add(usize::from(*ORDER.get_unchecked((*state).have as usize))) = 0;
                        (*state).have += 1;
                    }
                    (*state).next = (&raw mut (*state).codes).cast::<code>();
                    (*state).lencode = (*state).next;
                    (*state).lenbits = 7;
                    ret = zng_inflate_table(
                        CODES,
                        lens,
                        19,
                        &raw mut (*state).next,
                        &raw mut (*state).lenbits,
                        (&raw mut (*state).work).cast::<u16>(),
                    );
                    if ret != 0 {
                        bad!(c"invalid code lengths set");
                        continue;
                    }
                    (*state).have = 0;

                    /* get length and distance code code lengths */
                    'lens: while (*state).have < (*state).nlen + (*state).ndist {
                        loop {
                            here = *(*state).lencode.add(bits!((*state).lenbits) as usize);
                            if u32::from(here.bits) <= u32::from(bits) {
                                break;
                            }
                            pullbyte!();
                        }
                        if here.val < 16 {
                            dropbits!(here.bits);
                            *lens.add((*state).have as usize) = here.val;
                            (*state).have += 1;
                        } else {
                            if here.val == 16 {
                                needbits!(u32::from(here.bits) + 2);
                                dropbits!(here.bits);
                                if (*state).have == 0 {
                                    bad!(c"invalid bit length repeat");
                                    break 'lens;
                                }
                                len = u32::from(*lens.add((*state).have as usize - 1));
                                copy = 3 + bits!(2);
                                dropbits!(2);
                            } else if here.val == 17 {
                                needbits!(u32::from(here.bits) + 3);
                                dropbits!(here.bits);
                                len = 0;
                                copy = 3 + bits!(3);
                                dropbits!(3);
                            } else {
                                needbits!(u32::from(here.bits) + 7);
                                dropbits!(here.bits);
                                len = 0;
                                copy = 11 + bits!(7);
                                dropbits!(7);
                            }
                            if (*state).have + copy > (*state).nlen + (*state).ndist {
                                bad!(c"invalid bit length repeat");
                                break 'lens;
                            }
                            while copy != 0 {
                                copy -= 1;
                                *lens.add((*state).have as usize) = len as u16;
                                (*state).have += 1;
                            }
                        }
                    }

                    /* handle error breaks in while */
                    if (*state).mode == BAD {
                        continue;
                    }

                    /* check for end-of-block code (better have one) */
                    if *lens.add(256) == 0 {
                        bad!(c"invalid code -- missing end-of-block");
                        continue;
                    }

                    /* build code tables -- note: do not change the lenbits or distbits
                    values here (MAX_LEN_ROOT_BITS and 9) without reading the comments
                    in inftrees.h concerning the ENOUGH constants, which depend on
                    those values, and the refill comments in inffast_tpl.h, which
                    depend on lenbits never exceeding MAX_LEN_ROOT_BITS */
                    (*state).next = (&raw mut (*state).codes).cast::<code>();
                    (*state).lencode = (*state).next;
                    (*state).lenbits = MAX_LEN_ROOT_BITS;
                    ret = zng_inflate_table(
                        LENS,
                        lens,
                        (*state).nlen,
                        &raw mut (*state).next,
                        &raw mut (*state).lenbits,
                        (&raw mut (*state).work).cast::<u16>(),
                    );
                    if ret != 0 {
                        bad!(c"invalid literal/lengths set");
                        continue;
                    }
                    (*state).distcode = (*state).next;
                    (*state).distbits = 9;
                    ret = zng_inflate_table(
                        DISTS,
                        lens.add((*state).nlen as usize),
                        (*state).ndist,
                        &raw mut (*state).next,
                        &raw mut (*state).distbits,
                        (&raw mut (*state).work).cast::<u16>(),
                    );
                    if ret != 0 {
                        bad!(c"invalid distances set");
                        continue;
                    }
                    // C falls into LEN from here, which the loop reaches through the mode.
                    (*state).mode = LEN;
                }

                LEN => {
                    /* use inflate_fast() if we have enough input and output */
                    if have >= INFLATE_FAST_MIN_HAVE as u32 && left >= INFLATE_FAST_MIN_SAFE as u32
                    {
                        (*strm).next_out = put;
                        (*strm).avail_out = left;
                        (*strm).next_in = next;
                        (*strm).avail_in = have;
                        (*state).hold = hold;
                        (*state).bits = u32::from(bits);
                        if (*state).whave < (*state).wsize {
                            (*state).whave = (*state).wsize - left;
                        }
                        /* inflateBack() writes directly into the window, so out and window
                        always overlap. Use the safe variant, whose chunk copy functions
                        never overwrite window data needed by future back-references. */
                        functable::inflate_fast_safe(strm, (*state).wsize);
                        put = (*strm).next_out;
                        left = (*strm).avail_out;
                        next = (*strm).next_in;
                        have = (*strm).avail_in;
                        hold = (*state).hold;
                        bits = (*state).bits as bits_t;
                        continue;
                    }

                    /* get a literal, length, or end-of-block code */
                    loop {
                        here = *(*state).lencode.add(bits!((*state).lenbits) as usize);
                        if code_bits(here) <= u32::from(bits) {
                            break;
                        }
                        pullbyte!();
                    }
                    if here.op != 0 && (here.op & 0xf0) == 0 {
                        last = here;
                        let last_bits = code_bits(last);
                        loop {
                            here = *(*state).lencode.add(
                                usize::from(last.val)
                                    + (bits!(last_bits + u32::from(last.op & 15)) >> last_bits)
                                        as usize,
                            );
                            if last_bits + code_bits(here) <= u32::from(bits) {
                                break;
                            }
                            pullbyte!();
                        }
                        dropbits!(last_bits);
                    }
                    dropbits!(code_bits(here));
                    (*state).length = u32::from(here.val);

                    /* process literal */
                    if here.op == 0 {
                        room!();
                        *put = (*state).length as u8;
                        put = put.add(1);
                        left -= 1;
                        (*state).mode = LEN;
                        continue;
                    }

                    /* process end of block */
                    if here.op & 32 != 0 {
                        (*state).mode = TYPE;
                        continue;
                    }

                    /* invalid code */
                    if here.op & 64 != 0 {
                        bad!(c"invalid literal/length code");
                        continue;
                    }

                    /* length code -- get extra bits, if any */
                    (*state).extra = code_extra(here);
                    if (*state).extra != 0 {
                        needbits!((*state).extra);
                        (*state).length += bits!((*state).extra);
                        dropbits!((*state).extra);
                    }

                    /* get distance code */
                    loop {
                        here = *(*state).distcode.add(bits!((*state).distbits) as usize);
                        if code_bits(here) <= u32::from(bits) {
                            break;
                        }
                        pullbyte!();
                    }
                    if (here.op & 0xf0) == 0 {
                        last = here;
                        let last_bits = code_bits(last);
                        loop {
                            here = *(*state).distcode.add(
                                usize::from(last.val)
                                    + (bits!(last_bits + u32::from(last.op & 15)) >> last_bits)
                                        as usize,
                            );
                            if last_bits + code_bits(here) <= u32::from(bits) {
                                break;
                            }
                            pullbyte!();
                        }
                        dropbits!(last_bits);
                    }
                    dropbits!(code_bits(here));
                    if here.op & 64 != 0 {
                        bad!(c"invalid distance code");
                        continue;
                    }
                    (*state).offset = u32::from(here.val);
                    (*state).extra = code_extra(here);

                    /* get distance extra bits, if any */
                    if (*state).extra != 0 {
                        needbits!((*state).extra);
                        (*state).offset += bits!((*state).extra);
                        dropbits!((*state).extra);
                    }
                    if (*state).offset
                        > (*state)
                            .wsize
                            .wrapping_sub(if (*state).whave < (*state).wsize {
                                left
                            } else {
                                0
                            })
                    {
                        bad!(c"invalid distance too far back");
                        continue;
                    }

                    /* copy match from window to output */
                    loop {
                        room!();
                        copy = (*state).wsize - (*state).offset;
                        if copy < left {
                            from = put.add(copy as usize);
                            copy = left - copy;
                        } else {
                            from = put.sub((*state).offset as usize);
                            copy = left;
                        }
                        copy = copy.min((*state).length);
                        (*state).length -= copy;
                        left -= copy;
                        loop {
                            *put = *from;
                            put = put.add(1);
                            from = from.add(1);
                            copy = copy.wrapping_sub(1);
                            if copy == 0 {
                                break;
                            }
                        }
                        if (*state).length == 0 {
                            break;
                        }
                    }
                }

                MATCH => {
                    /* Copy back-reference that inflate_fast() could not complete due to
                    insufficient output space. state->length and state->offset were set
                    by the safe_mode MATCH bailout in inflate_fast(), which bails out
                    before validating the distance, so check it here. */
                    if (*state).offset
                        > (*state)
                            .wsize
                            .wrapping_sub(if (*state).whave < (*state).wsize {
                                left
                            } else {
                                0
                            })
                    {
                        bad!(c"invalid distance too far back");
                        continue;
                    }
                    loop {
                        room!();
                        copy = (*state).wsize - (*state).offset;
                        if copy < left {
                            from = put.add(copy as usize);
                            copy = left - copy;
                            copy = copy.min((*state).length);
                            put = chunkcopy_safe(put, from, copy as usize, put.add(left as usize));
                        } else {
                            copy = (*state).length.min(left);
                            put = functable::chunkmemset_safe(
                                put,
                                put.sub((*state).offset as usize),
                                copy as usize,
                                left as usize,
                            );
                        }
                        (*state).length -= copy;
                        left -= copy;
                        if (*state).length == 0 {
                            break;
                        }
                    }
                    (*state).mode = LEN;
                }

                DONE => {
                    /* inflate stream terminated properly */
                    ret = Z_STREAM_END;
                    break 'machine;
                }

                BAD => {
                    ret = Z_DATA_ERROR;
                    break 'machine;
                }

                /* can't happen, but makes compilers happy */
                _ => {
                    ret = Z_STREAM_ERROR;
                    break 'machine;
                }
            }
        }

        /* Write leftover output and return unused input */
        if left < (*state).wsize {
            let Some(output) = out else {
                missing_callback()
            };
            if output(out_desc, (*state).window, (*state).wsize - left) != 0 && ret == Z_STREAM_END
            {
                ret = Z_BUF_ERROR;
            }
        }
        (*strm).next_in = next;
        (*strm).avail_in = have;
        ret
    }
}

/// # Safety
///
/// `strm` must be null or a stream that inflateBackInit set up.
#[unsafe(export_name = prefix!("inflateBackEnd"))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn inflateBackEnd(strm: *mut z_stream) -> i32 {
    // SAFETY: the caller guarantees the stream and its state.
    unsafe {
        if strm.is_null() || (*strm).state.is_null() || (*strm).zfree.is_none() {
            return Z_STREAM_ERROR;
        }

        /* Free allocated buffers */
        free_inflate(strm);

        Z_OK
    }
}
