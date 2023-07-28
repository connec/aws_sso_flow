//! Cleaned up AWS SSO OIDC API.

use std::fmt;

use aws_config::SdkConfig;
use chrono::{DateTime, TimeZone, Utc};
use url::Url;

use crate::{cache, VerificationPrompt};

pub(crate) struct Client {
    inner: aws_sdk_ssooidc::Client,
}

impl Client {
    pub(crate) fn new(config: &SdkConfig) -> Self {
        Self {
            inner: aws_sdk_ssooidc::Client::new(config),
        }
    }

    pub(crate) async fn register_client(
        &self,
        request: RegisterClientRequest,
    ) -> Result<RegisterClientResponse, String> {
        self.inner
            .register_client()
            .client_name(request.client_name)
            .client_type("public")
            .send()
            .await
            .map_err(|error| error.to_string())
            .and_then(TryInto::try_into)
    }

    pub(crate) async fn create_token<V: VerificationPrompt>(
        &self,
        request: CreateTokenRequest,
        prompt: V,
    ) -> Result<CreateTokenResponse, CreateTokenError<V::Error>> {
        let client_id = request.client_id.clone();
        let client_secret = request.client_secret.clone();

        let start_device_authorization_response: StartDeviceAuthorizationResponse = self
            .inner
            .start_device_authorization()
            .client_id(request.client_id)
            .client_secret(request.client_secret)
            .start_url(request.start_url)
            .send()
            .await
            .map_err(|error| error.to_string())
            .and_then(TryInto::try_into)
            .map_err(CreateTokenError::Api)?;

        prompt
            .prompt(start_device_authorization_response.verification_uri_complete)
            .await
            .map_err(CreateTokenError::VerificationPrompt)?;

        let create_token_request = self
            .inner
            .create_token()
            .client_id(client_id)
            .client_secret(client_secret)
            .code(start_device_authorization_response.user_code)
            .device_code(start_device_authorization_response.device_code)
            .grant_type("urn:ietf:params:oauth:grant-type:device_code".to_string());
        loop {
            match create_token_request.clone().send().await {
                Ok(res) => break res.try_into().map_err(CreateTokenError::Api),
                Err(aws_sdk_ssooidc::error::SdkError::ServiceError(err))
                    if err.err().is_authorization_pending_exception() =>
                {
                    tokio::time::sleep(start_device_authorization_response.interval).await;
                }
                Err(aws_sdk_ssooidc::error::SdkError::ServiceError(err))
                    if err.err().is_expired_token_exception() =>
                {
                    return Err(CreateTokenError::VerificationPromptTimeout);
                }
                Err(error) => return Err(CreateTokenError::Api(error.to_string())),
            }
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

#[derive(Debug, Hash)]
pub(crate) struct RegisterClientRequest {
    pub(crate) client_name: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct RegisterClientResponse {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) client_secret_expires_at: DateTime<Utc>,
}

impl cache::Expiry for RegisterClientResponse {
    fn expires_at(&self) -> DateTime<Utc> {
        self.client_secret_expires_at
    }
}

impl TryFrom<aws_sdk_ssooidc::operation::register_client::RegisterClientOutput>
    for RegisterClientResponse
{
    type Error = String;

    fn try_from(
        res: aws_sdk_ssooidc::operation::register_client::RegisterClientOutput,
    ) -> Result<Self, Self::Error> {
        macro_rules! invalid_res {
            ($msg:literal) => {
                concat!("invalid RegisterClient response: ", $msg)
            };
        }

        let chrono::LocalResult::Single(client_secret_expires_at) = Utc.timestamp_opt(res.client_secret_expires_at, 0) else {
            panic!("invalid client_secret_expires_at");
        };
        Ok(Self {
            client_id: res.client_id.ok_or(invalid_res!("missing client_id"))?,
            client_secret: res
                .client_secret
                .ok_or(invalid_res!("missing client_secret"))?,
            client_secret_expires_at,
        })
    }
}

#[derive(Hash)]
pub(crate) struct CreateTokenRequest {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) start_url: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct CreateTokenResponse {
    pub(crate) access_token: String,
    pub(crate) expires_at: DateTime<Utc>,
}

impl cache::Expiry for CreateTokenResponse {
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl TryFrom<aws_sdk_ssooidc::operation::create_token::CreateTokenOutput> for CreateTokenResponse {
    type Error = String;

    fn try_from(
        res: aws_sdk_ssooidc::operation::create_token::CreateTokenOutput,
    ) -> Result<Self, Self::Error> {
        macro_rules! invalid_res {
            ($msg:literal) => {
                concat!("invalid CreateToken response: ", $msg)
            };
        }

        Ok(Self {
            access_token: res
                .access_token
                .ok_or(invalid_res!("missing access_token"))?,
            expires_at: Utc::now() + chrono::Duration::seconds(res.expires_in.into()),
        })
    }
}

#[derive(Debug)]
pub(crate) enum CreateTokenError<E> {
    Api(String),
    VerificationPrompt(E),
    VerificationPromptTimeout,
}

#[derive(Debug)]
struct StartDeviceAuthorizationResponse {
    device_code: String,
    interval: std::time::Duration,
    user_code: String,
    verification_uri_complete: Url,
}

impl TryFrom<aws_sdk_ssooidc::operation::start_device_authorization::StartDeviceAuthorizationOutput>
    for StartDeviceAuthorizationResponse
{
    type Error = String;

    fn try_from(
        res: aws_sdk_ssooidc::operation::start_device_authorization::StartDeviceAuthorizationOutput,
    ) -> Result<Self, Self::Error> {
        macro_rules! invalid_res {
            ($msg:literal) => {
                concat!("invalid StartDeviceAuthorization response: ", $msg)
            };
        }

        Ok(Self {
            device_code: res.device_code.ok_or(invalid_res!("missing device_code"))?,
            interval: std::time::Duration::from_secs(
                res.interval.try_into().expect("interval should fit u64"),
            ),
            user_code: res.user_code.ok_or(invalid_res!("missing user_code"))?,
            verification_uri_complete: res
                .verification_uri_complete
                .ok_or(invalid_res!("missing verification_uri_complete"))?
                .parse()
                .map_err(|error| {
                    format!(
                        invalid_res!("verification_uri_complete is not a valid URL ({})"),
                        error
                    )
                })?,
        })
    }
}
