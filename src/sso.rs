//! Cleaned up AWS SSO API.

use std::fmt;

use aws_config::SdkConfig;
use chrono::{DateTime, TimeZone, Utc};

use crate::cache::Expiry;

pub(crate) struct Client {
    inner: aws_sdk_sso::Client,
}

impl Client {
    pub(crate) fn new(config: &SdkConfig) -> Self {
        Self {
            inner: aws_sdk_sso::Client::new(config),
        }
    }

    pub(crate) async fn get_role_credentials(
        &self,
        request: GetRoleCredentialsRequest,
    ) -> Result<GetRoleCredentialsResponse, String> {
        self.inner
            .get_role_credentials()
            .access_token(request.access_token)
            .account_id(request.account_id)
            .role_name(request.role_name)
            .send()
            .await
            .map_err(|error| error.to_string())
            .and_then(TryInto::try_into)
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

#[derive(Hash)]
pub(crate) struct GetRoleCredentialsRequest {
    pub(crate) access_token: String,
    pub(crate) account_id: String,
    pub(crate) role_name: String,
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

impl TryFrom<aws_sdk_sso::output::GetRoleCredentialsOutput> for GetRoleCredentialsResponse {
    type Error = String;

    fn try_from(res: aws_sdk_sso::output::GetRoleCredentialsOutput) -> Result<Self, Self::Error> {
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
            expires_at: Utc.timestamp_millis(credentials.expiration),
        })
    }
}
