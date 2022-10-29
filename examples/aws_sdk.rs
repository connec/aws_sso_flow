use std::convert::Infallible;

use aws_config::meta::credentials::CredentialsProviderChain;
use aws_types_integration::credentials::ProvideCredentials;

use aws_sso_flow::SsoFlow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let flow = SsoFlow::builder().verification_prompt(|url| async move {
        println!("Go to {url} to sign in with SSO");
        Ok::<_, Infallible>(())
    });
    let provider = CredentialsProviderChain::first_try("SsoFlow", flow)
        .or_default_provider()
        .await;

    let credentials = provider.provide_credentials().await?;

    dbg!(credentials);

    Ok(())
}
