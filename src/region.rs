// A wrapper around `aws_types::Region` to avoid exposing it in the API.

use std::{borrow::Cow, fmt};

// Use `Region` from `aws_sdk_sso` to avoid depending directly on `aws_types`. It's hoped this will
// make it possible to integrate with other versions of aws-sdk than the one used to implement this
// crate, since the `aws-types` dependency can be more flexible.
use aws_sdk_sso::Region as SdkRegion;

/// An AWS region.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Region(pub(crate) SdkRegion);

impl Region {
    /// Construct a new `Region` for the given string.
    pub fn new(region: impl Into<Cow<'static, str>>) -> Self {
        Self(SdkRegion::new(region))
    }
}

impl AsRef<str> for Region {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl fmt::Debug for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
