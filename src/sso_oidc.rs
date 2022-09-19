//! Cleaned up AWS SSO OIDC API.

use chrono::{DateTime, TimeZone, Utc};
use rusoto_core::{credential::StaticProvider, DispatchSignedRequest, RusotoError};
use rusoto_sso_oidc::{SsoOidc, SsoOidcClient};
use url::Url;

use crate::{cache, Region, VerificationPrompt};

pub(crate) struct Client {
    inner: SsoOidcClient,
}

impl Client {
    pub(crate) fn new<D>(request_dispatcher: D, region: Region) -> Self
    where
        D: DispatchSignedRequest + Send + Sync + 'static,
    {
        let anonymous = StaticProvider::new_minimal("".to_string(), "".to_string());
        Self {
            inner: SsoOidcClient::new_with(request_dispatcher, anonymous, region.0),
        }
    }

    pub(crate) async fn register_client(
        &self,
        request: RegisterClientRequest,
    ) -> Result<RegisterClientResponse, String> {
        self.inner
            .register_client(request.into())
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
            .start_device_authorization(request.into())
            .await
            .map_err(|error| error.to_string())
            .and_then(TryInto::try_into)
            .map_err(CreateTokenError::Api)?;

        prompt
            .prompt(start_device_authorization_response.verification_uri_complete)
            .await
            .map_err(CreateTokenError::VerificationPrompt)?;

        let create_token_request = rusoto_sso_oidc::CreateTokenRequest {
            client_id,
            client_secret,
            code: Some(start_device_authorization_response.user_code),
            device_code: start_device_authorization_response.device_code,
            grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            redirect_uri: None,
            refresh_token: None,
            scope: None,
        };
        loop {
            match self.inner.create_token(create_token_request.clone()).await {
                Ok(res) => break res.try_into().map_err(CreateTokenError::Api),
                Err(RusotoError::Service(
                    rusoto_sso_oidc::CreateTokenError::AuthorizationPending(_),
                )) => {
                    tokio::time::sleep(start_device_authorization_response.interval).await;
                }
                Err(RusotoError::Service(rusoto_sso_oidc::CreateTokenError::ExpiredToken(_))) => {
                    return Err(CreateTokenError::VerificationPromptTimeout);
                }
                Err(error) => return Err(CreateTokenError::Api(error.to_string())),
            }
        }
    }
}

#[derive(Debug, Hash)]
pub(crate) struct RegisterClientRequest {
    pub(crate) client_name: String,
}

impl From<RegisterClientRequest> for rusoto_sso_oidc::RegisterClientRequest {
    fn from(req: RegisterClientRequest) -> Self {
        Self {
            client_name: req.client_name,
            client_type: "public".to_string(),
            scopes: None,
        }
    }
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

impl TryFrom<rusoto_sso_oidc::RegisterClientResponse> for RegisterClientResponse {
    type Error = String;

    fn try_from(res: rusoto_sso_oidc::RegisterClientResponse) -> Result<Self, Self::Error> {
        macro_rules! invalid_res {
            ($msg:literal) => {
                concat!("invalid RegisterClient response: ", $msg)
            };
        }

        Ok(Self {
            client_id: res.client_id.ok_or(invalid_res!("missing client_id"))?,
            client_secret: res
                .client_secret
                .ok_or(invalid_res!("missing client_secret"))?,
            client_secret_expires_at: res
                .client_secret_expires_at
                .map(|secs| Utc.timestamp(secs, 0))
                .ok_or(invalid_res!("missing client_secret_expires_at"))?,
        })
    }
}

#[derive(Hash)]
pub(crate) struct CreateTokenRequest {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) start_url: String,
}

impl From<CreateTokenRequest> for rusoto_sso_oidc::StartDeviceAuthorizationRequest {
    fn from(req: CreateTokenRequest) -> Self {
        Self {
            client_id: req.client_id,
            client_secret: req.client_secret,
            start_url: req.start_url,
        }
    }
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

impl TryFrom<rusoto_sso_oidc::CreateTokenResponse> for CreateTokenResponse {
    type Error = String;

    fn try_from(res: rusoto_sso_oidc::CreateTokenResponse) -> Result<Self, Self::Error> {
        macro_rules! invalid_res {
            ($msg:literal) => {
                concat!("invalid CreateToken response: ", $msg)
            };
        }

        Ok(Self {
            access_token: res
                .access_token
                .ok_or(invalid_res!("missing access_token"))?,
            expires_at: Utc::now()
                + chrono::Duration::seconds(
                    res.expires_in.ok_or(invalid_res!("missing expires_in"))?,
                ),
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

impl TryFrom<rusoto_sso_oidc::StartDeviceAuthorizationResponse>
    for StartDeviceAuthorizationResponse
{
    type Error = String;

    fn try_from(
        res: rusoto_sso_oidc::StartDeviceAuthorizationResponse,
    ) -> Result<Self, Self::Error> {
        macro_rules! invalid_res {
            ($msg:literal) => {
                concat!("invalid StartDeviceAuthorization response: ", $msg)
            };
        }

        Ok(Self {
            device_code: res.device_code.ok_or(invalid_res!("missing device_code"))?,
            interval: std::time::Duration::from_secs(
                res.interval
                    .ok_or(invalid_res!("missing interval"))?
                    .try_into()
                    .expect("interval should fit u64"),
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
