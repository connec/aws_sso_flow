use std::convert::Infallible;

use aws_sso_flow::SsoFlow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sso = SsoFlow::new(|url| async move {
        println!("Go to {url} to sign in with SSO");
        Ok::<_, Infallible>(())
    })
    .await?;

    let credentials = sso.authenticate().await?;

    dbg!(credentials);

    Ok(())
}
