mod blocklist;
mod ip_list;

pub use blocklist::Blocklist;
pub use ip_list::Domain;

use ip_list::Scanlist;
use openssl::ssl::{
    self, HandshakeError, MidHandshakeSslStream, SslConnector, SslMethod, SslStream,
};
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
            .map_err(|e| e.to_string())?;

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
            Err(err) => return ConnectionInfo::from_tcp_stream_err(err.to_string()),
        };

        let con = self.template_connector.clone();

        match con.connect(&addr.1.to_str(), stream) {
            Ok(s) => ConnectionInfo::from_tls_info(TLSConnectionInfo::from_ssl_stream(s)),
            Err(err) => {
                ConnectionInfo::from_tls_info(TLSConnectionInfo::from_midhandshake_ssl_stream(err))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConnectionInfoList(Vec<ConnectionInfo>);

#[derive(Serialize, Deserialize, Debug)]
struct ConnectionInfo {
    connection_failure: bool,
    connection_failure_reason: Option<String>,
    tls_connection_info: Option<TLSConnectionInfo>,
}

impl ConnectionInfo {
    fn from_tcp_stream_err(reason: String) -> Self {
        ConnectionInfo {
            connection_failure: true,
            connection_failure_reason: Some(reason),
            tls_connection_info: None,
        }
    }

    fn from_tls_info(tls_info: TLSConnectionInfo) -> Self {
        ConnectionInfo {
            connection_failure: false,
            connection_failure_reason: None,
            tls_connection_info: Some(tls_info),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TLSConnectionInfo {
    domain: String,
    ip_address: String,
    tls_version: String,
    valid_certificate_chain: bool,
    certificate_chain: String,
}

impl TLSConnectionInfo {
    fn from_ssl_stream(s: SslStream<TcpStream>) -> Self {
        todo!();
    }

    fn from_midhandshake_ssl_stream(s: HandshakeError<TcpStream>) -> Self {
        todo!();
    }
}
