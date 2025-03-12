use std::fs;
use std::io::{BufReader, Read};
use anyhow::{Context, Result};
use minifb::{Window, WindowOptions};
use rustls_pki_types::{CertificateDer, TrustAnchor};
use rustls_pki_types::pem::PemObject;
use tokio::{self, net::TcpStream};
use tokio::io::AsyncReadExt;
use tracing::Level;
use webpki::DerTypeId::Certificate;
use vnc::{PixelFormat, Rect, VncConnector, VncEvent, X11Event, ClientMouseEvent, ClientKeyEvent};
use webpki::{anchor_from_trusted_cert, EndEntityCert};

struct CanvasUtils {
    window: Window,
    video: Vec<u32>,
    width: u32,
    height: u32,
}

impl CanvasUtils {
    fn new() -> Result<Self> {
        Ok(Self {
            window: Window::new(
                "mstsc-rs Remote Desktop in Rust",
                800_usize,
                600_usize,
                WindowOptions::default(),
            )
            .with_context(|| "Unable to create window".to_string())?,
            video: vec![],
            width: 800,
            height: 600,
        })
    }

    fn init(&mut self, width: u32, height: u32) -> Result<()> {
        let mut window = Window::new(
            "mstsc-rs Remote Desktop in Rust",
            width as usize,
            height as usize,
            WindowOptions::default(),
        )
        .with_context(|| "Unable to create window")?;
        window.limit_update_rate(Some(std::time::Duration::from_micros(16600)));
        self.window = window;
        self.width = width;
        self.height = height;
        self.video.resize(height as usize * width as usize, 0);
        Ok(())
    }

    fn draw(&mut self, rect: Rect, data: Vec<u8>) -> Result<()> {
        // since we set the PixelFormat as bgra
        // the pixels must be sent in [blue, green, red, alpha] in the network order

        let mut s_idx = 0;
        for y in rect.y..rect.y + rect.height {
            let mut d_idx = y as usize * self.width as usize + rect.x as usize;

            for _ in rect.x..rect.x + rect.width {
                self.video[d_idx] =
                    u32::from_le_bytes(data[s_idx..s_idx + 4].try_into().unwrap()) & 0x00_ff_ff_ff;
                s_idx += 4;
                d_idx += 1;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.window
            .update_with_buffer(&self.video, self.width as usize, self.height as usize)
            .with_context(|| "Unable to update screen buffer")?;
        Ok(())
    }

    fn copy(&mut self, dst: Rect, src: Rect) -> Result<()> {
        println!("Copy");
        let mut tmp = vec![0; src.width as usize * src.height as usize];
        let mut tmp_idx = 0;
        for y in 0..src.height as usize {
            let mut s_idx = (src.y as usize + y) * self.width as usize + src.x as usize;
            for _ in 0..src.width {
                tmp[tmp_idx] = self.video[s_idx];
                tmp_idx += 1;
                s_idx += 1;
            }
        }
        tmp_idx = 0;
        for y in 0..src.height as usize {
            let mut d_idx = (dst.y as usize + y) * self.width as usize + dst.x as usize;
            for _ in 0..src.width {
                self.video[d_idx] = tmp[tmp_idx];
                tmp_idx += 1;
                d_idx += 1;
            }
        }
        Ok(())
    }

    fn close(&self) {}

    fn hande_vnc_event(&mut self, event: VncEvent) -> Result<()> {
        match event {
            VncEvent::SetResolution(screen) => {
                tracing::info!("Resize {:?}", screen);
                self.init(screen.width as u32, screen.height as u32)?
            }
            VncEvent::RawImage(rect, data) => {
                self.draw(rect, data)?;
            }
            VncEvent::Bell => {
                tracing::warn!("Bell event got, but ignore it");
            }
            VncEvent::SetPixelFormat(_) => unreachable!(),
            VncEvent::Copy(dst, src) => {
                self.copy(dst, src)?;
            }
            VncEvent::JpegImage(_rect, _data) => {
                tracing::warn!("Jpeg event got, but ignore it");
            }
            VncEvent::SetCursor(rect, data) => {
                if rect.width != 0 {
                    self.draw(rect, data)?;
                }
            }
            VncEvent::Text(string) => {
                tracing::info!("Got clipboard message {}", string);
            }
            _ => tracing::error!("{:?}", event),
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create tracing subscriber
    #[cfg(debug_assertions)]
    let subscriber = tracing_subscriber::fmt()
        .pretty()
        .with_max_level(Level::TRACE)
        .finish();
    #[cfg(not(debug_assertions))]
    let subscriber = tracing_subscriber::fmt()
        .pretty()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let tcp = TcpStream::connect("192.168.200.160:5900").await?;

    let pem_string = "-----BEGIN CERTIFICATE-----
MIIDVzCCAj+gAwIBAgIUOqPSfcoY0ZbPb2fgTFk6gFIyQe8wDQYJKoZIhvcNAQEL
BQAwVDELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0ppYW5nc3UxEDAOBgNVBAcMB05h
bmppbmcxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTAz
MTExNDQ0MzJaFw0yNjAzMTExNDQ0MzJaMFQxCzAJBgNVBAYTAkNOMRAwDgYDVQQI
DAdKaWFuZ3N1MRAwDgYDVQQHDAdOYW5qaW5nMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC
fItZUlqRq5Iz5C2HbpVVC+srQ35KRBKfpRmnZbCLuw21A84HK2GGhg+WWTVk5/R3
mkbAQzhNjo9pBqzVzIb1YTEnKre7Z/HBXlh6XwZwSCpgwul6krKILS4erEK+kOkv
v+MBrkgsbkfS80qGM3ijPVXUtBYv5rrcr2e5SrQtafqRHKLFWSrMv+0VoEQ5HKDb
UHuOljWw0+NOCDQ5aVZsjzOWFDYT3rgAOvucPUiq4dEwA9wJm+ojAClC4O1ofYUa
BDBj+LVZ4zIWf6QqAQQLLNlurqGUPQI7F6srWCRKSJIm6RwbpVOBHASTuhpRA+PZ
WN4L6MorDkCnmoy8Kg1BAgMBAAGjITAfMB0GA1UdDgQWBBQSbmgnCOOzP10DFg35
pa9nL2wyBzANBgkqhkiG9w0BAQsFAAOCAQEAI26VPxdbQ5ncSzVUIu18ZBuXWy2F
Jt0/J3lm+mrfc5QGbAnbOHMR4q7NWEjReUu1DIU0DhibBW4zhYOsNQv3NSPKJkcB
cgwE7rxwLAMM9PwXs3WlXVpBXnxju7QR3iBMYinsZzsIuXDKeyOnCicUOGf431GQ
mkEHSN6k0WJF9IXUNqI6tDIhW4Cps1a04KpxXiSu7KdBNle6QHJaE25WuNKEYywy
JNqNmjbWeA5+v50Vkh2JA8H2xKH3vqbO9wt5Y8T99zc7RyUt6UfToU71d97GglG9
EtUYbAPGtuVelmg1bYnf3KOXtJNEza67e/gVLxjDXAukIyJLXWD4x+TdkA==
-----END CERTIFICATE-----";

    let pem = pem::parse(pem_string)?;

    // Convert the certificate bytes to DER format
    let der_bytes = pem.contents();

    // Create a CertificateDer object from the DER bytes
    let cert_der = CertificateDer::from(der_bytes);

    let vnc = VncConnector::new(tcp)
        .set_auth_method(async move { Ok(vec!["root".to_string(), "1234".to_string()]) })
        .add_encoding(vnc::VncEncoding::Tight)
        .add_encoding(vnc::VncEncoding::Zrle)
        .add_encoding(vnc::VncEncoding::CopyRect)
        .add_encoding(vnc::VncEncoding::Raw)
        .add_root_store(
            cert_der
        )
        .set_sni_name("192.168.200.160".to_string())
        .allow_shared(true)
        .set_pixel_format(PixelFormat::bgra())
        .build()?
        .try_start()
        .await?
        .finish()?;

    let mut canvas = CanvasUtils::new()?;

    let mut now = std::time::Instant::now();

    loop {
        match vnc.poll_event().await {
            Ok(Some(e)) => {
                let _ = canvas.hande_vnc_event(e);
            }
            Ok(None) => (),
            Err(e) => {
                tracing::error!("{}", e.to_string());
                break;
            }
        }
        if now.elapsed().as_millis() > 16 {
            let _ = canvas.flush();
            let _ = vnc.input(X11Event::Refresh).await;
            now = std::time::Instant::now();
        }
    }
    canvas.close();
    let _ = vnc.close().await;
    Ok(())
}
