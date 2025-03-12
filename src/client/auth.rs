use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;

use super::security;
use crate::{VncError, VncVersion};
use rustls::pki_types::{ServerName, TrustAnchor};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{client::TlsStream, rustls::{ClientConfig, RootCertStore}, TlsConnector};

mod sni;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum SecurityType {
    Invalid = 0,
    None = 1,
    VncAuth = 2,
    RA2 = 5,
    RA2ne = 6,
    Tight = 16,
    Ultra = 17,
    Tls = 18,
    VeNCrypt = 19,
    GtkVncSasl = 20,
    Md5Hash = 21,
    ColinDeanXvp = 22,
    RSAAES256 = 129
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum VeNCryptSecurityType {
    Plain = 256,
    TLSNone,
    TLSVnc,
    TLSPlain,
    X509None,
    X509Vnc,
    X509Plain,
    TLSSASL,
    X509SASL,
}

impl TryFrom<u8> for SecurityType {
    type Error = VncError;
    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 | 1 | 2 | 5 | 6 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 129 => {
                Ok(unsafe { std::mem::transmute::<u8, SecurityType>(num) })
            }
            invalid => Err(VncError::InvalidSecurityType(invalid)),
        }
    }
}

impl From<SecurityType> for u8 {
    fn from(e: SecurityType) -> Self {
        e as u8
    }
}

impl TryFrom<u32> for VeNCryptSecurityType {
    type Error = VncError;
    fn try_from(num: u32) -> Result<Self, Self::Error> {
        match num {
            256..=264 => Ok(unsafe { std::mem::transmute(num) }),
            invalid => Err(VncError::InvalidVeNCSubtype(invalid)),
        }
    }
}

impl From<VeNCryptSecurityType> for u32 {
    fn from(e: VeNCryptSecurityType) -> Self {
        e as u32
    }
}

impl SecurityType {
    pub(super) async fn read<S>(reader: &mut S, version: &VncVersion) -> Result<Vec<Self>, VncError>
    where
        S: AsyncRead + Unpin,
    {
        match version {
            VncVersion::RFB33 => {
                let security_type = reader.read_u32().await?;
                let security_type = (security_type as u8).try_into()?;
                if let SecurityType::Invalid = security_type {
                    let _ = reader.read_u32().await?;
                    let mut err_msg = String::new();
                    reader.read_to_string(&mut err_msg).await?;
                    return Err(VncError::General(err_msg));
                }
                Ok(vec![security_type])
            }
            _ => {
                // +--------------------------+-------------+--------------------------+
                // | No. of bytes             | Type        | Description              |
                // |                          | [Value]     |                          |
                // +--------------------------+-------------+--------------------------+
                // | 1                        | U8          | number-of-security-types |
                // | number-of-security-types | U8 array    | security-types           |
                // +--------------------------+-------------+--------------------------+
                let num = reader.read_u8().await?;

                if num == 0 {
                    let _ = reader.read_u32().await?;
                    let mut err_msg = String::new();
                    reader.read_to_string(&mut err_msg).await?;
                    return Err(VncError::General(err_msg));
                }
                let mut sec_types = vec![];
                for _ in 0..num {
                    sec_types.push(reader.read_u8().await?.try_into()?);
                }
                tracing::trace!("Server supported security type: {:?}", sec_types);
                Ok(sec_types)
            }
        }
    }

    pub(super) async fn write<S>(&self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        writer.write_all(&[(*self).into()]).await?;
        Ok(())
    }
}

#[allow(dead_code)]
#[repr(u32)]
pub(super) enum AuthResult {
    Ok = 0,
    Failed = 1,
    TooMany = 2,
}

impl From<u32> for AuthResult {
    fn from(num: u32) -> Self {
        unsafe { std::mem::transmute(num) }
    }
}

impl From<AuthResult> for u32 {
    fn from(e: AuthResult) -> Self {
        e as u32
    }
}

pub(super) struct AuthHelper {
    challenge: [u8; 16],
    key: [u8; 8],
}

impl AuthHelper {
    pub(super) async fn read<S>(reader: &mut S, credential: &str) -> Result<Self, VncError>
    where
        S: AsyncRead + Unpin,
    {
        let mut challenge = [0; 16];
        reader.read_exact(&mut challenge).await?;

        let credential_len = credential.len();
        let mut key = [0u8; 8];
        for (i, key_i) in key.iter_mut().enumerate() {
            let c = if i < credential_len {
                credential.as_bytes()[i]
            } else {
                0
            };
            let mut cs = 0u8;
            for j in 0..8 {
                cs |= ((c >> j) & 1) << (7 - j)
            }
            *key_i = cs;
        }

        Ok(Self { challenge, key })
    }

    pub(super) async fn write<S>(&self, writer: &mut S) -> Result<(), VncError>
    where
        S: AsyncWrite + Unpin,
    {
        let encrypted = security::des::encrypt(&self.challenge, &self.key);
        writer.write_all(&encrypted).await?;
        Ok(())
    }

    pub(super) async fn finish<S>(self, reader: &mut S) -> Result<AuthResult, VncError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let result = reader.read_u32().await?;
        Ok(result.into())
    }
}

pub(super) struct VeNCAuthHelper<S>
where
S: AsyncRead + AsyncWrite + Unpin,
{
    version: [u8; 2],
    subtype: VeNCryptSecurityType,
    pub tls_stream: Option<TlsStream<S>>
}

impl<S> VeNCAuthHelper<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(super) async fn new(stream: &mut S) -> Result<Self, VncError>

    {
        let mut version:[u8; 2] = [0; 2];
        stream.read_exact(&mut version).await?;
        if (version[0], version[1]) != (0, 2) {
            return Err(VncError::UnsupportedVeNCryptVersion);
        }

        stream.write_all(&[0, 2]).await?;

        let response = stream.read_u8().await?;

        if response != 0 {
            return Err(VncError::UnsupportedVeNCryptVersion);
        }

        let subtypelen = stream.read_u8().await?;
        let mut subtypes: Vec<VeNCryptSecurityType> = Vec::new();
        for _ in 0..subtypelen {
            let subtype = stream.read_u32().await?.try_into()?;
            subtypes.push(subtype);
        }

        if !subtypes.contains(&VeNCryptSecurityType::X509Plain) {
            return Err(VncError::UnsupportedVeNCryptVersion);
        }

        stream.write_u32(VeNCryptSecurityType::X509Plain.into()).await?;

        let response = stream.read_u8().await?;
        if response != 1 {
            return Err(VncError::UnsupportedVeNCryptVersion);
        }

        Ok(Self{version, subtype: VeNCryptSecurityType::X509Plain, tls_stream: None})
    }

    pub(super) async fn tls_handshake(& mut self, stream: S, host: String, custom_store : RootCertStore) -> Result<(), VncError>
    {
        assert!(self.subtype == VeNCryptSecurityType::X509Plain && self.version == [0, 2]);

        let mut roots = custom_store.clone();

        roots.roots.extend_from_slice(webpki_roots::TLS_SERVER_ROOTS);

        let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots.clone())).build().map_err(|err| VncError::TlsHandshakeError(format!("{}", err)))?;
        let verifier = Arc::new(sni::NoServerNameVerification::new(inner));

        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        config.dangerous().set_certificate_verifier(verifier);

        let connector = TlsConnector::from(Arc::new(config));
        let tls_stream = connector.connect(ServerName::try_from(host).unwrap(), stream).await;

        if let Ok(tlstream) = tls_stream {
            self.tls_stream = Some(tlstream);
        } else {
            return Err(VncError::TlsHandshakeError(format!("{0}", tls_stream.err().unwrap())));
        }


        Ok(())
    }

    pub(super) async fn finish(&mut self, username: &str, password: &str) -> Result<AuthResult, VncError>
    {
        self.tls_stream.as_mut().unwrap().write_u32(username.len() as u32).await?;
        self.tls_stream.as_mut().unwrap().write_u32(password.len() as u32).await?;
        self.tls_stream.as_mut().unwrap().write_all(username.as_bytes()).await?;
        self.tls_stream.as_mut().unwrap().write_all(password.as_bytes()).await?;

        let result = self.tls_stream.as_mut().unwrap().read_u32().await?;

        Ok(result.into())
    }
}