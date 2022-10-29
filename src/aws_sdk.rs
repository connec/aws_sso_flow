use std::fmt;

use aws_types_integration::{
    credentials::{
        future::ProvideCredentials as ProvideCredentialsFut, CredentialsError, ProvideCredentials,
    },
    Credentials,
};

use crate::{SessionCredentials, SsoConfigSource, SsoFlow, SsoFlowBuilder, VerificationPrompt};

/// Provide credentials via an [`SsoFlowBuilder`].
///
/// If SSO configuration can't be loaded for any reason, errors are converted to
/// [`CredentialsError::CredentialsNotLoaded`], which won't stop resolution if the builder is used
/// as part of a credentials chain. If an SSO profile is loaded successfully, then any subsequent
/// authentication errors are converted to [`CredentialsError::ProviderError`] which will stop
/// resolution.
///
/// The aws-sdk's SSO credentials provider behaves similarly but relies on a fresh SSO OIDC access
/// token being cached (at at `~/.aws/sso/cache/{sha1(start_url)}.json`). As such, `SsoFlowBuilder`s
/// should be set to run *before* the default provider chain.
///
/// ```no_run
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use aws_types_integration as aws_types;
/// use std::convert::Infallible;
///
/// use aws_config::meta::credentials::CredentialsProviderChain;
/// use aws_types::credentials::ProvideCredentials;
/// use aws_sso_flow::{Region, SsoConfig, SsoFlow};
///
/// // Configure an SSO flow that loads SSO from shared config and prints the verification URL
/// let flow = SsoFlow::builder().verification_prompt(|url| async move {
///     println!("Go to {url} to sign in with SSO");
///     Ok::<_, Infallible>(())
/// });
///
/// // Try the SSO flow *first*, and fall back to the default provider chain
/// let provider = CredentialsProviderChain::first_try("SsoFlow", flow)
///     .or_default_provider()
///     .await;
///
/// // `flow` will be attempted first, falling back to the default chain if SSO configuration can't
/// // be loaded.
/// let creds = provider.provide_credentials().await?;
///
/// // Configure an SSO flow that uses static configuration
/// let flow = SsoFlow::builder()
///     .config(SsoConfig {
///         region: Region::new("eu-west-1"),
///         start_url: "myorg.signin.amazonaws.com/start".to_string(),
///         account_id: "012345678910".to_string(),
///         role_name: "developer".to_string(),
///     })
///     .verification_prompt(|url| async move {
///         println!("Go to {url} to sign in with SSO");
///         Ok::<_, Infallible>(())
///     });
///
/// // Try the default chain, and fall back to the statically configured SSO flow
/// let provider = CredentialsProviderChain::default_provider()
///     .await
///     .or_else("SsoFlow", flow);
///
/// // the default chain will be attempted first, falling back to `flow` only if no default
/// // providers could be loaded.
/// let creds = provider.provide_credentials().await?;
/// # Ok(()) }
/// ```
impl<S, V> ProvideCredentials for SsoFlowBuilder<S, V>
where
    S: SsoConfigSource + Clone + fmt::Debug + Send + Sync,
    S::Future: Send,
    V: VerificationPrompt + Clone + Send + Sync,
{
    fn provide_credentials<'a>(&'a self) -> ProvideCredentialsFut<'a>
    where
        Self: 'a,
    {
        ProvideCredentialsFut::new(async {
            let flow = self
                .clone()
                .build()
                .await
                .map_err(CredentialsError::not_loaded)?;

            let creds = flow
                .authenticate()
                .await
                .map(Into::into)
                .map_err(CredentialsError::provider_error)?;

            Ok(creds)
        })
    }
}

impl<V> ProvideCredentials for SsoFlow<V>
where
    V: VerificationPrompt + Send + Sync,
{
    fn provide_credentials<'a>(
        &'a self,
    ) -> aws_types_integration::credentials::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        ProvideCredentialsFut::new(async {
            let creds = self
                .authenticate()
                .await
                .map(Into::into)
                .map_err(CredentialsError::provider_error)?;

            Ok(creds)
        })
    }
}

impl From<SessionCredentials> for Credentials {
    fn from(creds: SessionCredentials) -> Self {
        Credentials::new(
            creds.access_key_id,
            creds.secret_access_key,
            Some(creds.session_token),
            Some(creds.expires_at.into()),
            "SsoFlow",
        )
    }
}
