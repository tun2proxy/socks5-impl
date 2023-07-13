/// A proxy authentication method.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthMethod {
    /// No authentication required.
    NoAuth = 0x00,
    /// GSS API.
    GssApi = 0x01,
    /// A username + password authentication.
    UserPass = 0x02,
    /// IANA reserved.
    IanaReserved(u8),
    /// A private authentication method.
    Private(u8),
    /// X'FF' NO ACCEPTABLE METHODS
    NoAcceptableMethods = 0xff,
}

impl From<u8> for AuthMethod {
    fn from(value: u8) -> Self {
        match value {
            0x00 => AuthMethod::NoAuth,
            0x01 => AuthMethod::GssApi,
            0x02 => AuthMethod::UserPass,
            0x03..=0x7f => AuthMethod::IanaReserved(value),
            0x80..=0xfe => AuthMethod::Private(value),
            0xff => AuthMethod::NoAcceptableMethods,
        }
    }
}

impl From<AuthMethod> for u8 {
    fn from(value: AuthMethod) -> Self {
        match value {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UserPass => 0x02,
            AuthMethod::IanaReserved(value) => value,
            AuthMethod::Private(value) => value,
            AuthMethod::NoAcceptableMethods => 0xff,
        }
    }
}

impl From<&AuthMethod> for u8 {
    fn from(value: &AuthMethod) -> Self {
        match value {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UserPass => 0x02,
            AuthMethod::IanaReserved(value) => *value,
            AuthMethod::Private(value) => *value,
            AuthMethod::NoAcceptableMethods => 0xff,
        }
    }
}
