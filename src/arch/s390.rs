#[cfg(feature = "s390-dfltcc-deflate")]
pub(crate) mod dfltcc_common;
#[cfg(feature = "s390-dfltcc-deflate")]
pub(crate) mod dfltcc_deflate;
#[cfg(feature = "s390-dfltcc-inflate")]
pub(crate) mod dfltcc_inflate;
