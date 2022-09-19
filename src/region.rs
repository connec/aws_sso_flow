//! A wrapper around [`rusoto_core::Region`], to avoid exposing it in the API.

use std::fmt;

/// An AWS region.
#[derive(Clone, Default, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Region(pub(crate) rusoto_core::Region);

impl fmt::Debug for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.name())
    }
}

impl std::str::FromStr for Region {
    type Err = ParseRegionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Region).map_err(ParseRegionError)
    }
}

/// The error returned when trying to parse a [`Region`] from an invalid `&str`.
#[derive(PartialEq)]
pub struct ParseRegionError(rusoto_core::region::ParseRegionError);

impl fmt::Debug for ParseRegionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for ParseRegionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for ParseRegionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}
