//! Cleaned up AWS SSO API.

use chrono::{DateTime, TimeZone, Utc};
use rusoto_core::{credential::StaticProvider, DispatchSignedRequest};
use rusoto_sso::{Sso, SsoClient};

use crate::{cache::Expiry, Region};

pub(crate) struct Client {
    inner: SsoClient,
}

impl Client {
    pub(crate) fn new<D>(request_dispatcher: D, region: Region) -> Self
    where
        D: DispatchSignedRequest + Send + Sync + 'static,
    {
        let anonymous = StaticProvider::new_minimal("".to_string(), "".to_string());
        Self {
            inner: SsoClient::new_with(request_dispatcher, anonymous, region.0),
        }
    }

    pub(crate) async fn get_role_credentials(
        &self,
        request: GetRoleCredentialsRequest,
    ) -> Result<GetRoleCredentialsResponse, String> {
        self.inner
            .get_role_credentials(request.into())
            .await
            .map_err(|error| error.to_string())
            .and_then(TryInto::try_into)
    }
}

#[derive(Hash)]
pub(crate) struct GetRoleCredentialsRequest {
    pub(crate) access_token: String,
    pub(crate) account_id: String,
    pub(crate) role_name: String,
}

impl From<GetRoleCredentialsRequest> for rusoto_sso::GetRoleCredentialsRequest {
    fn from(req: GetRoleCredentialsRequest) -> Self {
        Self {
            access_token: req.access_token,
            account_id: req.account_id,
            role_name: req.role_name,
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct GetRoleCredentialsResponse {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    pub(crate) session_token: String,
    pub(crate) expires_at: DateTime<Utc>,
}

impl Expiry for GetRoleCredentialsResponse {
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl TryFrom<rusoto_sso::GetRoleCredentialsResponse> for GetRoleCredentialsResponse {
    type Error = String;

    fn try_from(res: rusoto_sso::GetRoleCredentialsResponse) -> Result<Self, Self::Error> {
        macro_rules! invalid_res {
            ($msg:literal) => {
                concat!("invalid GetRoleCredentials response: ", $msg)
            };
        }

        let credentials = res
            .role_credentials
            .ok_or(invalid_res!("missing role_credentials"))?;
        Ok(Self {
            access_key_id: credentials
                .access_key_id
                .ok_or(invalid_res!("missing access_key_id"))?,
            secret_access_key: credentials
                .secret_access_key
                .ok_or(invalid_res!("missing secret_access_key"))?,
            session_token: credentials
                .session_token
                .ok_or(invalid_res!("missing session_token"))?,
            expires_at: credentials
                .expiration
                .map(|millis| Utc.timestamp_millis(millis))
                .ok_or(invalid_res!("missing expires_at"))?,
        })
    }
}
