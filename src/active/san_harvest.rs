use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use x509_parser::prelude::*;
use tracing::{debug, warn};

/// Connect to an IP on port 443, complete TLS handshake, extract SANs from the certificate.
pub async fn harvest_san(addr: SocketAddr, domain: &str) -> Vec<String> {
    let mut results = Vec::new();

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = match ServerName::try_from(domain.to_string()) {
        Ok(sn) => sn,
        Err(_) => return results,
    };

    let tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(addr),
    ).await {
        Ok(Ok(stream)) => stream,
        _ => return results,
    };

    let tls = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connector.connect(server_name, tcp),
    ).await {
        Ok(Ok(stream)) => stream,
        _ => return results,
    };

    // get_ref() returns (&IO, &ClientConnection)
    let (_, conn) = tls.get_ref();
    let certs = match conn.peer_certificates() {
        Some(certs) if !certs.is_empty() => certs,
        _ => return results,
    };

    // Parse the leaf certificate
    let cert_der = &certs[0];
    let (_, cert) = match X509Certificate::from_der(cert_der.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            warn!(addr = %addr, error = %e, "failed to parse cert");
            return results;
        }
    };

    // Extract SANs
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                let dns = dns.to_lowercase();
                debug!(addr = %addr, san = %dns, "found SAN");
                results.push(dns);
            }
        }
    }

    // Also check the CN in subject
    for attr in cert.subject().iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            let cn = cn.to_lowercase();
            if cn.contains('.') {
                results.push(cn);
            }
        }
    }

    results
}

/// Scan multiple IPs for TLS SANs concurrently.
pub async fn harvest_sans_batch(
    ips: &[std::net::IpAddr],
    domain: &str,
    concurrency: usize,
) -> Vec<String> {
    use futures::stream::{self, StreamExt};

    let results: Vec<Vec<String>> = stream::iter(ips.iter())
        .map(|ip| {
            let addr = SocketAddr::new(*ip, 443);
            let domain = domain.to_string();
            async move {
                harvest_san(addr, &domain).await
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results.into_iter().flatten().collect()
}

/// TLS verifier that accepts any certificate — we want the SAN data, not trust validation.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
