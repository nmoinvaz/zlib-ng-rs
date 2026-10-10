//! zconf-ng.h -- configuration of the zlib-ng compression library
//! Copyright (C) 1995-2026 Jean-loup Gailly, Mark Adler
//! For conditions of distribution and use, see copyright notice in zlib.h

#![allow(non_camel_case_types)]

// The build measures both offset types from the generated C header.
#[cfg(feature = "z-off-t-32")]
pub type z_off_t = i32;
#[cfg(not(feature = "z-off-t-32"))]
pub type z_off_t = i64;

#[cfg(feature = "z-off64-t-32")]
pub type z_off64_t = i32;
#[cfg(not(feature = "z-off64-t-32"))]
pub type z_off64_t = i64;
