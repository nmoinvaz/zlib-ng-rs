pub(crate) mod generic;
#[cfg(any(feature = "s390-dfltcc-deflate", feature = "s390-dfltcc-inflate"))]
pub(crate) mod s390;
