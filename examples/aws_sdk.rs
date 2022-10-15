use std::{convert::Infallible, fmt};

use aws_config::meta::credentials::CredentialsProviderChain;
use aws_sso_flow::{SsoConfigSource, SsoFlow, SsoFlowBuilder, VerificationPrompt};
use aws_types::{
    credentials::{CredentialsError, ProvideCredentials},
    Credentials,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let flow = SsoFlow::builder().verification_prompt(|url| async move {
        println!("Go to {url} to sign in with SSO");
        Ok::<_, Infallible>(())
    });
    let provider = CredentialsProviderChain::first_try("SsoFlow", SsoFlowProvider(flow))
        .or_default_provider()
        .await;

    let credentials = provider.provide_credentials().await?;

    dbg!(credentials);

    Ok(())
}

struct SsoFlowProvider<S, V>(SsoFlowBuilder<S, V>);

impl<S, V> fmt::Debug for SsoFlowProvider<S, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SsoFlowProvider").finish_non_exhaustive()
    }
}

impl<S, V> ProvideCredentials for SsoFlowProvider<S, V>
where
    S: SsoConfigSource + Clone + Send + Sync,
    S::Future: Send,
    V: VerificationPrompt + Send + Sync,
{
    fn provide_credentials<'a>(&'a self) -> aws_types::credentials::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        aws_types::credentials::future::ProvideCredentials::new(async move {
            let flow = self
                .0
                .clone()
                .build()
                .await
                .map_err(CredentialsError::not_loaded)?;

            flow.authenticate()
                .await
                .map(|creds| {
                    Credentials::new(
                        creds.access_key_id,
                        creds.secret_access_key,
                        Some(creds.session_token),
                        Some(creds.expires_at.into()),
                        "SsoFlow",
                    )
                })
                .map_err(CredentialsError::provider_error)
        })
    }
}
