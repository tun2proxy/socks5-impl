use super::{Address, UserKey};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ProxyParameters {
    pub proxy_type: ProxyType,
    pub addr: Address,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub credentials: Option<UserKey>,
}

impl Default for ProxyParameters {
    fn default() -> Self {
        ProxyParameters {
            proxy_type: ProxyType::Socks5,
            addr: "127.0.0.1:1080".parse().unwrap(),
            credentials: None,
        }
    }
}

impl std::fmt::Display for ProxyParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth = match &self.credentials {
            Some(creds) => format!("{creds}"),
            None => "".to_owned(),
        };
        if auth.is_empty() {
            write!(f, "{}://{}", self.proxy_type, self.addr)
        } else {
            write!(f, "{}://{}@{}", self.proxy_type, auth, self.addr)
        }
    }
}

impl TryFrom<&str> for ProxyParameters {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        if s == "none" {
            return Ok(ProxyParameters {
                proxy_type: ProxyType::None,
                addr: "0.0.0.0:0".parse().unwrap(),
                credentials: None,
            });
        }

        let e = format!("`{s}` is not a valid proxy URL");
        let url = url::Url::parse(s).map_err(|_| Error::from(&e))?;
        let e = format!("`{s}` does not contain a host");
        let host = url.host_str().ok_or(Error::from(e))?;

        let e = format!("`{s}` does not contain a port");
        let port = url.port_or_known_default().ok_or(Error::from(&e))?;

        let addr = (host, port).into();

        let credentials = if url.username() == "" && url.password().is_none() {
            None
        } else {
            use percent_encoding::percent_decode;
            let username = percent_decode(url.username().as_bytes()).decode_utf8()?;
            let password = percent_decode(url.password().unwrap_or("").as_bytes()).decode_utf8()?;
            Some(UserKey::new(username, password))
        };

        let proxy_type = url.scheme().to_ascii_lowercase().as_str().try_into()?;

        Ok(ProxyParameters {
            proxy_type,
            addr,
            credentials,
        })
    }
}

impl std::str::FromStr for ProxyParameters {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::try_from(s)
    }
}

#[repr(C)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub enum ProxyType {
    Http = 0,
    Socks4,
    #[default]
    Socks5,
    None,
}

impl TryFrom<&str> for ProxyType {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "http" => Ok(ProxyType::Http),
            "socks4" => Ok(ProxyType::Socks4),
            "socks5" => Ok(ProxyType::Socks5),
            "none" => Ok(ProxyType::None),
            scheme => Err(Error::from(&format!("`{scheme}` is an invalid proxy type"))),
        }
    }
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::Socks4 => write!(f, "socks4"),
            ProxyType::Socks5 => write!(f, "socks5"),
            ProxyType::Http => write!(f, "http"),
            ProxyType::None => write!(f, "none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_proxy_parameters() {
        let parameters = ProxyParameters::default();

        assert_eq!(parameters.proxy_type, ProxyType::Socks5);
        assert_eq!(parameters.addr, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(parameters.credentials, None);
        assert_eq!(parameters.to_string(), "socks5://127.0.0.1:1080");
    }

    #[test]
    fn parse_without_credentials() {
        let parameters = "socks5://123.45.67.89:1080".parse::<ProxyParameters>().unwrap();
        assert_eq!(parameters.proxy_type, ProxyType::Socks5);
        assert_eq!(parameters.addr, ("123.45.67.89", 1080).into());
        assert_eq!(parameters.addr.get_type(), crate::protocol::AddressType::IPv4);
        assert_eq!(parameters.credentials, None);
        assert_eq!(parameters.to_string(), "socks5://123.45.67.89:1080");

        let parameters = "socks5://proxy.example.com:1080".parse::<ProxyParameters>().unwrap();

        assert_eq!(parameters.proxy_type, ProxyType::Socks5);
        assert_eq!(parameters.addr, ("proxy.example.com", 1080).into());
        assert_eq!(parameters.credentials, None);
        assert_eq!(parameters.to_string(), "socks5://proxy.example.com:1080");

        let parameters = "http://proxy.example.com:8080".parse::<ProxyParameters>().unwrap();
        assert_eq!(parameters.proxy_type, ProxyType::Http);
        assert_eq!(parameters.addr, ("proxy.example.com", 8080).into());
        assert_eq!(parameters.credentials, None);
        assert_eq!(parameters.to_string(), "http://proxy.example.com:8080");

        let parameters = "http://proxy.example.com".parse::<ProxyParameters>().unwrap();
        assert_eq!(parameters.proxy_type, ProxyType::Http);
        assert_eq!(parameters.addr, ("proxy.example.com", 80).into());
        assert_eq!(parameters.credentials, None);
        assert_eq!(parameters.to_string(), "http://proxy.example.com:80");

        assert!("socks5://proxy.example.com".parse::<ProxyParameters>().is_err());
    }

    #[test]
    fn parse_with_credentials() {
        let parameters = "socks5://user:password@proxy.example.com:1080".parse::<ProxyParameters>().unwrap();
        assert_eq!(parameters.proxy_type, ProxyType::Socks5);
        assert_eq!(parameters.addr, ("proxy.example.com", 1080).into());
        assert_eq!(parameters.credentials, Some(UserKey::new("user", "password")));
        assert_eq!(parameters.to_string(), "socks5://user:password@proxy.example.com:1080");

        let parameters = "socks5://user@123.45.67.89:1080".parse::<ProxyParameters>().unwrap();
        assert_eq!(parameters.proxy_type, ProxyType::Socks5);
        assert_eq!(parameters.addr, ("123.45.67.89", 1080).into());
        assert_eq!(parameters.credentials, Some(UserKey::new("user", "")));
        assert_eq!(parameters.to_string(), "socks5://user@123.45.67.89:1080");

        let parameters = "socks5://:password@123.45.67.89:1080".parse::<ProxyParameters>().unwrap();
        assert_eq!(parameters.proxy_type, ProxyType::Socks5);
        assert_eq!(parameters.addr, ("123.45.67.89", 1080).into());
        assert_eq!(parameters.credentials, Some(UserKey::new("", "password")));
        assert_eq!(parameters.to_string(), "socks5://:password@123.45.67.89:1080");
    }

    #[test]
    fn parse_with_percent_encoded_credentials() {
        let parameters = "socks5://user%40name:pa%24%24@proxy.example.com:1080"
            .parse::<ProxyParameters>()
            .unwrap();

        assert_eq!(parameters.proxy_type, ProxyType::Socks5);
        assert_eq!(parameters.addr, ("proxy.example.com", 1080).into());
        assert_eq!(parameters.credentials, Some(UserKey::new("user@name", "pa$$")));
        assert_eq!(parameters.to_string(), "socks5://user%40name:pa%24%24@proxy.example.com:1080");
    }

    #[test]
    fn parse_none_proxy() {
        let parameters = "none".parse::<ProxyParameters>().unwrap();

        assert_eq!(parameters.proxy_type, ProxyType::None);
        assert_eq!(parameters.addr, "0.0.0.0:0".parse().unwrap());
        assert_eq!(parameters.credentials, None);
        assert_eq!(parameters.to_string(), "none://0.0.0.0:0");
    }

    #[test]
    fn parse_invalid_proxy_type() {
        let err = "ftp://proxy.example.com:21".parse::<ProxyParameters>().unwrap_err();
        assert!(format!("{err}").contains("invalid proxy type"));
    }
}
