use std::fmt;

use chrono::{DateTime, Utc};

use crate::{cache::Expiry, sso};

/// AWS session credentials.
///
/// The fields of this struct are obviously pretty sensitive, and should be handled with care.
/// The secret and session token are not printed in `Debug` output.
#[allow(clippy::module_name_repetitions)]
pub struct SessionCredentials {
    /// The access key ID.
    pub access_key_id: String,

    /// The secret access key.
    pub secret_access_key: String,

    /// The session token.
    pub session_token: String,

    /// When the credentials expire.
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SessionCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl Expiry for SessionCredentials {
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl From<sso::GetRoleCredentialsResponse> for SessionCredentials {
    fn from(res: sso::GetRoleCredentialsResponse) -> Self {
        Self {
            access_key_id: res.access_key_id,
            secret_access_key: res.secret_access_key,
            session_token: res.session_token,
            expires_at: res.expires_at,
        }
    }
}
