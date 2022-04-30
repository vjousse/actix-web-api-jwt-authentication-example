//! Extractor for the "Bearer" HTTP Authentication Scheme

use std::default::Default;

use actix_utils::future::{ready, Ready};
use actix_web::{dev::Payload, http::header::Header, FromRequest, HttpRequest};
use actix_web_httpauth::extractors::{AuthExtractorConfig, AuthenticationError};
use actix_web_httpauth::headers::{authorization, www_authenticate::bearer};

/// [BearerAuth](./struct/BearerAuth.html) extractor configuration.
#[derive(Debug, Clone, Default)]
pub struct Config(bearer::Bearer);

//impl Config {
//    /// Set challenge `scope` attribute.
//    ///
//    /// The `"scope"` attribute is a space-delimited list of case-sensitive
//    /// scope values indicating the required scope of the access token for
//    /// accessing the requested resource.
//    pub fn scope<T: Into<Cow<'static, str>>>(mut self, value: T) -> Config {
//        self.0.scope = Some(value.into());
//        self
//    }

//    /// Set challenge `realm` attribute.
//    ///
//    /// The "realm" attribute indicates the scope of protection in the manner
//    /// described in HTTP/1.1 [RFC2617](https://tools.ietf.org/html/rfc2617#section-1.2).
//    pub fn realm<T: Into<Cow<'static, str>>>(mut self, value: T) -> Config {
//        self.0.realm = Some(value.into());
//        self
//    }
//}

impl AsRef<bearer::Bearer> for Config {
    fn as_ref(&self) -> &bearer::Bearer {
        &self.0
    }
}

impl AuthExtractorConfig for Config {
    type Inner = bearer::Bearer;

    fn into_inner(self) -> Self::Inner {
        self.0
    }
}

#[derive(Debug, Clone)]
pub struct BearerUserAuth(authorization::Bearer);

impl BearerUserAuth {
    /// Returns bearer token provided by client.
    pub fn token(&self) -> &str {
        self.0.token()
    }
}

impl FromRequest for BearerUserAuth {
    type Future = Ready<Result<Self, Self::Error>>;
    type Error = AuthenticationError<bearer::Bearer>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> <Self as FromRequest>::Future {
        ready(
            authorization::Authorization::<authorization::Bearer>::parse(req)
                .map(|auth| BearerUserAuth(auth.into_scheme()))
                .map_err(|_| {
                    let bearer = req
                        .app_data::<Config>()
                        .map(|config| config.0.clone())
                        .unwrap_or_else(Default::default);

                    AuthenticationError::new(bearer)
                }),
        )
    }
}
