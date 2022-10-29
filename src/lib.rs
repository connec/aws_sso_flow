#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, clippy::pedantic)]

//! AWS SSO authentication flow.
//!
//! See [`authenticate`] for the main entrypoint to the crate.
//!
//! ```no_run
//! # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::convert::Infallible;
//!
//! let credentials = aws_sso_flow::authenticate(|url| async move {
//!     println!("Go to {url} to sign in with SSO");
//!     Ok::<_, Infallible>(())
//! }).await?;
//! # Ok(()) }
//! ```

#[cfg_attr(docsrs, doc(cfg(feature = "aws-sdk")))]
#[cfg(feature = "aws-sdk")]
mod aws_sdk;
mod builder;
mod cache;
mod credentials;
mod flow;
mod profile;
mod region;
#[cfg_attr(docsrs, doc(cfg(feature = "rusoto")))]
#[cfg(feature = "rusoto")]
mod rusoto;
mod sso;
mod sso_oidc;

use std::fmt;

pub use crate::{
    builder::{SsoConfig, SsoConfigSource, SsoFlowBuilder},
    credentials::SessionCredentials,
    flow::{SsoApiError, SsoCacheError, SsoFlow, SsoFlowError, VerificationPrompt},
    profile::{ProfileSource, SsoProfileError},
    region::Region,
};

#[cfg(feature = "rusoto")]
pub use crate::rusoto::ChainProvider;

const _: () = assert!(
    const_str::equal!(env!("CARGO_PKG_VERSION_MAJOR"), "0"),
    "client naming scheme needs updated for 1.0"
);
const CLIENT_NAME: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "@",
    "0.",
    env!("CARGO_PKG_VERSION_MINOR")
);

/// Perform a default AWS SSO authentication flow with the given `verification_prompt`.
///
/// The prompt should direct the user to the given URL, where they will be asked to grant
/// access. Intermediate tokens are cached, and if the cache is still valid the user may not
/// need to be prompted. Attempts to obtain credentials will timeout if the user hasn't followed the
/// verification URL and granted access before the user code expires (default 10 mins).
///
/// SSO configuration is sourced from AWS shared config (located with `AWS_CONFIG_FILE` and
/// `AWS_PROFILE`) and intermediate tokens are cached in the user's OS cache directory in
/// `aws_sso_flow/0.1/*`. The cache format is considered part of the crate's API.
///
/// For more flexible configuration see [`SsoFlowBuilder`].
///
/// # Example
///
/// A simple prompt implementation could print the URL and ask the user to visit it:
///
/// ```no_run
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::convert::Infallible;
///
/// let credentials = aws_sso_flow::authenticate(|url| async move {
///     println!("Go to {url} to sign in with SSO");
///     Ok::<_, Infallible>(())
/// }).await?;
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// An error is returned if a profile cannot be loaded, if it is missing SSO configuration, or if
/// there's a failure during the authentication flow. You can separate configuration errors from
/// authentication flow errors by using [`SsoFlow::new`] instead.
pub async fn authenticate<V: VerificationPrompt>(
    verification_prompt: V,
) -> Result<SessionCredentials, SsoError<V::Error>> {
    let credentials = SsoFlow::new(verification_prompt)
        .await?
        .authenticate()
        .await?;
    Ok(credentials)
}

/// An error indicating either misconfiguration or a failure during authentication.
#[derive(Debug)]
pub enum SsoError<P: std::error::Error + Send + Sync + 'static> {
    /// SSO configuration was missing or invalid.
    Config(SsoProfileError),

    /// Failure during authentication.
    Flow(SsoFlowError<P>),
}

impl<P: std::error::Error + Send + Sync + 'static> fmt::Display for SsoError<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Config(error) => error.fmt(f),
            Self::Flow(error) => error.fmt(f),
        }
    }
}

impl<P: std::error::Error + Send + Sync + 'static> std::error::Error for SsoError<P> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => error.source(),
            Self::Flow(error) => error.source(),
        }
    }
}

impl<P: std::error::Error + Send + Sync + 'static> From<SsoProfileError> for SsoError<P> {
    fn from(error: SsoProfileError) -> Self {
        Self::Config(error)
    }
}

impl<P: std::error::Error + Send + Sync + 'static> From<SsoFlowError<P>> for SsoError<P> {
    fn from(error: SsoFlowError<P>) -> Self {
        Self::Flow(error)
    }
}
