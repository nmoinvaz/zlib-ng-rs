//! crc32_chorba_p.h -- crc32 chorba interface
//! Copyright (C) 2021 Nathan Moinvaziri
//! For conditions of distribution and use, see copyright notice in zlib.h

/* Size thresholds for Chorba algorithm variants */

pub(crate) const CHORBA_LARGE_THRESHOLD: usize = size_of::<chorba_word_t>() * 64 * 1024;
#[cfg(target_pointer_width = "64")]
pub(crate) const CHORBA_MEDIUM_UPPER_THRESHOLD: usize = 32768;
#[cfg(target_pointer_width = "64")]
pub(crate) const CHORBA_MEDIUM_LOWER_THRESHOLD: usize = 8192;

#[cfg(target_pointer_width = "64")]
pub(crate) const CHORBA_SMALL_THRESHOLD: usize = 72;
#[cfg(target_pointer_width = "64")]
pub(crate) const CHORBA_W: usize = 8;
#[cfg(target_pointer_width = "64")]
#[allow(non_camel_case_types)]
pub(crate) type chorba_word_t = u64;

#[cfg(not(target_pointer_width = "64"))]
pub(crate) const CHORBA_SMALL_THRESHOLD: usize = 80;
#[cfg(not(target_pointer_width = "64"))]
pub(crate) const CHORBA_W: usize = 4;
#[cfg(not(target_pointer_width = "64"))]
#[allow(non_camel_case_types)]
pub(crate) type chorba_word_t = u32;
