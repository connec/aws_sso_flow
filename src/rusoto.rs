use std::fmt;

use async_trait::async_trait;
use rusoto_credential::{AwsCredentials, CredentialsError, ProvideAwsCredentials};

use crate::{
    SessionCredentials, SsoConfigSource, SsoFlow, SsoFlowBuilder,
    VerificationPrompt,
};

#[async_trait]
impl<S, V> ProvideAwsCredentials for SsoFlowBuilder<S, V>
where
    S: SsoConfigSource + Clone + Send + Sync,
    S::Future: Send,
    V: VerificationPrompt + Clone + Send + Sync,
{
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        self.clone()
            .build()
            .await
            .map_err(CredentialsError::new)?
            .authenticate()
            .await
            .map(Into::into)
            .map_err(CredentialsError::new)
    }
}

#[async_trait]
impl<V: VerificationPrompt> ProvideAwsCredentials for SsoFlow<V> {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        self.authenticate()
            .await
            .map(Into::into)
            .map_err(CredentialsError::new)
    }
}

impl From<SessionCredentials> for AwsCredentials {
    fn from(credentials: SessionCredentials) -> Self {
        Self::new(
            credentials.access_key_id,
            credentials.secret_access_key,
            Some(credentials.session_token),
            Some(credentials.expires_at),
        )
    }
}

/// A generalised version of [`rusoto_credential::ChainProvider`] that provides AWS credentials from
/// multiple arbitrary sources.
///
/// # Example
///
/// To exhaust the default rusoto `ChainProvider` before falling back to SSO credentials you could
/// use:
///
/// ```no_run
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::convert::Infallible;
///
/// use aws_sso_flow::{ChainProvider, SsoFlow};
/// use rusoto_credential::ProvideAwsCredentials;
///
/// let mut provider = ChainProvider::new()
///     .push(rusoto_credential::ChainProvider::new())
///     .push(SsoFlow::builder().verification_prompt(|url| async move {
///         println!("Go to {url} to sign in");
///         Ok::<_, Infallible>(())
///     }));
///
/// let credentials = provider.credentials().await?;
/// # Ok(()) }
/// ```
#[derive(Default)]
pub struct ChainProvider {
    providers: Vec<Box<dyn ProvideAwsCredentials + Send + Sync>>,
}

impl ChainProvider {
    /// Construct a new (empty) `ChainProvider`.
    ///
    /// Trying to fetch credentials from an empty provider will always fail. Providers can be added
    /// with [`push`](Self::push).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a credentials provider to the chain.
    ///
    /// The new provider will be invoked if all the previously `push`ed providers fail.
    #[must_use]
    pub fn push<P>(mut self, provider: P) -> Self
    where
        P: ProvideAwsCredentials + Send + Sync + 'static,
    {
        self.providers.push(Box::new(provider));
        self
    }
}

impl fmt::Debug for ChainProvider {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ChainProvider")
            .field(
                "providers",
                &format_args!("[<{} entries>]", self.providers.len()),
            )
            .finish()
    }
}

#[async_trait]
impl ProvideAwsCredentials for ChainProvider {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        let mut errors = vec![];
        for provider in &self.providers {
            match provider.credentials().await {
                Ok(credentials) => return Ok(credentials),
                Err(error) => errors.push(error),
            }
        }

        let error_messages: Vec<_> = errors.iter().map(|error| format!("- {}", error)).collect();
        Err(CredentialsError::new(format!(
            "Couldn't find AWS credentials through any configured provider; all errors:\n\n{}",
            error_messages.join("\n")
        )))
    }
}
