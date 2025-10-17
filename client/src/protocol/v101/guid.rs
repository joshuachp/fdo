use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;

use crate::protocol::Hex;

/// Guid is implemented as a 128-bit cryptographically strong random number.
///
/// The Guid type identifies a Device during onboarding, and is replaced each time onboarding is successful in the Transfer Ownership 2 (TO2) protocol.
///
/// ```cddl
/// Guid = bstr .size 16
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) struct Guid(ByteArray<16>);

impl Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Guid")
            .field(&Hex::new(self.0.as_slice()))
            .finish()
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Hex::new(self.0.as_slice()), f)
    }
}
