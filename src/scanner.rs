mod blocklist;
mod ip_list;

pub use blocklist::Blocklist;
pub use ip_list::Domain;

use ip_list::Scanlist;
use openssl::ssl::{
    self, HandshakeError, MidHandshakeSslStream, SslConnector, SslMethod, SslStream,
};
use openssl::stack::StackRef;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub struct IpDomainPair(pub Ipv4Addr, pub Domain);

pub struct Scanner {
    scanlist: Scanlist,
    template_connector: SslConnector,
    destination_port: u16,
    timeout: Duration,
}

impl Scanner {
    pub fn new(
        addresses: Vec<IpDomainPair>,
        blocklist: blocklist::Blocklist,
        rootstore: PathBuf,
        port: u16,
        timeout: Duration,
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
        })
    }

    /// Starts the scan, consuming the scanner.
    pub fn start_scan(self) -> ConnectionInfoList {
        let mut results: Vec<_> = Vec::new();
        for ipdomain in self.scanlist.iter() {
            results.push(self.scan(ipdomain));
        }
        ConnectionInfoList(results)
    }

    /// Performs the scan on the ip address in `IpDomainPair`
    fn scan(&self, addr: &IpDomainPair) -> ConnectionInfo {
        // create tcp stream
        let stream = match TcpStream::connect_timeout(
            &SocketAddr::new(addr.0.into(), self.destination_port),
            self.timeout,
        ) {
            Ok(s) => s,
            Err(err) => return ConnectionInfo::from_tcp_stream_err(addr, err.to_string()),
        };

        let con = self.template_connector.clone();

        match con.connect(&addr.1.to_str(), stream) {
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
    certificate_chain: Option<Vec<String>>,
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

    fn cert_chain_to_string(chain: Option<&StackRef<X509>>) -> Option<Vec<String>> {
        let mut chain_vec = Vec::new();

        for cert in chain? {
            chain_vec.push(
                cert.to_text()
                    .map_or("".to_string(), |b| String::from_utf8_lossy(&b).into_owned()),
            );
        }
        Some(chain_vec)
    }
}
