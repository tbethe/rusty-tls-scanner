mod blocklist;
mod ip_list;

pub use blocklist::Blocklist;
pub use ip_list::Domain;

use ip_list::Scanlist;
use log::debug;
use openssl::ssl::{
    self, HandshakeError, MidHandshakeSslStream, SslConnector, SslMethod, SslStream,
};
use openssl::stack::StackRef;
use openssl::x509::{X509Ref, X509};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub struct IpDomainPair(pub Ipv4Addr, pub Domain);

pub struct Scanner {
    scanlist: Scanlist,
    template_connector: SslConnector,
    destination_port: u16,
    timeout: Duration,
    threads: u64,
}

impl Scanner {
    pub fn new(
        addresses: Vec<IpDomainPair>,
        blocklist: blocklist::Blocklist,
        rootstore: PathBuf,
        port: u16,
        timeout: Duration,
        threads: u64,
    ) -> Result<Self, String> {
        // Build the ssl connector that will serve as a template.
        let mut conn_builder: ssl::SslConnectorBuilder =
            ssl::SslConnector::builder(SslMethod::tls_client()).map_err(|e| e.to_string())?;

        // configure rootstore to use
        conn_builder
            .set_ca_file(rootstore)
            .map_err(|_| "Could not read the rootstore")?;

        let template_connector = conn_builder.build();

        Ok(Scanner {
            scanlist: Scanlist::new(addresses, blocklist),
            template_connector,
            destination_port: port,
            timeout,
            threads,
        })
    }

    /// Starts the scan, consuming the scanner.
    pub fn start_scan(self) -> ConnectionInfoList {
        let scan_list = Arc::new(Mutex::new(self.scanlist));
        let results = Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for n in 0..self.threads {
            let timeout = self.timeout;
            let port = self.destination_port;
            let sl = Arc::clone(&scan_list);
            let res = Arc::clone(&results);
            let con = self.template_connector.clone();
            handles.push(thread::spawn(move || {
                debug!("Started thread {}", n);
                loop {
                    let mut guard = sl.lock().unwrap();
                    let ipdomain = match guard.next() {
                        Some(a) => a,
                        None => break,
                    };
                    // let go of the lock.
                    std::mem::drop(guard);

                    debug!("[Thread {}] Scanning {:?}", n, ipdomain);
                    let connector = con.clone();
                    let tls_info = Scanner::scan(&ipdomain, port, connector, timeout);
                    res.lock().unwrap().push(tls_info);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        ConnectionInfoList(Arc::try_unwrap(results).unwrap().into_inner().unwrap())
    }

    /// Performs the scan on the ip address in `IpDomainPair`
    fn scan(
        addr: &IpDomainPair,
        port: u16,
        connector: SslConnector,
        timeout: Duration,
    ) -> ConnectionInfo {
        // create tcp stream
        let stream =
            match TcpStream::connect_timeout(&SocketAddr::new(addr.0.into(), port), timeout) {
                Ok(s) => s,
                Err(err) => return ConnectionInfo::from_tcp_stream_err(addr, err.to_string()),
            };

        match connector.connect(&addr.1.to_str(), stream) {
            Ok(s) => ConnectionInfo::from_tls_info(addr, TLSConnectionInfo::from_ssl_stream(s)),
            Err(err) => match err {
                HandshakeError::SetupFailure(err_stack) => {
                    ConnectionInfo::from_tcp_stream_err(addr, err_stack.to_string())
                }
                HandshakeError::Failure(midhandshake) => ConnectionInfo::from_tls_info(
                    addr,
                    TLSConnectionInfo::from_midhandshake_ssl_stream(midhandshake),
                ),
                HandshakeError::WouldBlock(midhandshake) => ConnectionInfo::from_tls_info(
                    addr,
                    TLSConnectionInfo::from_midhandshake_ssl_stream(midhandshake),
                ),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectionInfoList(Vec<ConnectionInfo>);

#[derive(Serialize, Deserialize, Debug)]
struct ConnectionInfo {
    domain: String,
    ip_address: String,
    connection_failure: bool,
    connection_failure_reason: Option<String>,
    tls_connection_info: Option<TLSConnectionInfo>,
}

impl ConnectionInfo {
    fn from_tcp_stream_err(ipdomain: &IpDomainPair, reason: String) -> Self {
        let domain = ipdomain.1.to_str();
        let ip_address = ipdomain.0.to_string();
        ConnectionInfo {
            domain,
            ip_address,
            connection_failure: true,
            connection_failure_reason: Some(reason),
            tls_connection_info: None,
        }
    }

    fn from_tls_info(ipdomain: &IpDomainPair, tls_info: TLSConnectionInfo) -> Self {
        let domain = ipdomain.1.to_str();
        let ip_address = ipdomain.0.to_string();
        ConnectionInfo {
            domain,
            ip_address,
            connection_failure: false,
            connection_failure_reason: None,
            tls_connection_info: Some(tls_info),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TLSConnectionInfo {
    handshake_status: String,
    handshake_failure_reason: Option<String>,
    tls_version: String,
    valid_certificate_chain: String,
    certificate_chain: Option<CertificateChain>,
}

impl TLSConnectionInfo {
    fn from_ssl_stream(s: SslStream<TcpStream>) -> Self {
        let ssl = s.ssl();

        TLSConnectionInfo {
            handshake_status: "Completed".to_string(),
            handshake_failure_reason: None,
            tls_version: ssl.version_str().to_string(),
            valid_certificate_chain: ssl.verify_result().to_string(),
            certificate_chain: Self::cert_chain_to_string(ssl.verified_chain()),
        }
    }

    fn from_midhandshake_ssl_stream(s: MidHandshakeSslStream<TcpStream>) -> Self {
        let ssl = s.ssl();
        TLSConnectionInfo {
            handshake_status: "Failed".to_string(),
            handshake_failure_reason: Some(s.error().to_string()),
            tls_version: ssl.version_str().to_string(),
            valid_certificate_chain: ssl.verify_result().to_string(),
            certificate_chain: Self::cert_chain_to_string(ssl.verified_chain()),
        }
    }

    fn cert_chain_to_string(chain: Option<&StackRef<X509>>) -> Option<CertificateChain> {
        let mut chain_vec = Vec::new();

        for cert in chain? {
            chain_vec.push(Certificate::from_x509(cert));
        }
        Some(CertificateChain { chain: chain_vec })
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct CertificateChain {
    chain: Vec<Certificate>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Certificate {
    subject_name: Vec<String>,
    issuer_name: String,
    not_after: String,
    not_before: String,
    text: String,
}

impl Certificate {
    fn from_x509(cert: &X509Ref) -> Self {
        Certificate {
            subject_name: cert
                .subject_name()
                .entries()
                .map(|e| {
                    e.data()
                        .as_utf8()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|_| "".to_string())
                })
                .collect(),
            issuer_name: cert
                .issuer_name()
                .entries()
                .map(|e| {
                    e.data()
                        .as_utf8()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|_| "".to_string())
                })
                .collect(),
            not_after: cert.not_after().to_string(),
            not_before: cert.not_before().to_string(),
            text: String::from_utf8_lossy(&cert.to_text().unwrap_or_else(|_| Vec::new()))
                .to_string(),
        }
    }
}
