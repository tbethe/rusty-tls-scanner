mod blocklist;
mod ip_list;

pub use blocklist::Blocklist;
pub use ip_list::Domain;

use ip_list::Scanlist;
use openssl::ssl::{self, HandshakeError, SslConnector, SslMethod, SslRef};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
pub struct IpDomainPair(pub Ipv4Addr, pub Domain);

pub struct Scanner {
    scanlist: Scanlist,
    output_dir: PathBuf,
    template_connector: SslConnector,
    destination_port: u16,
    timeout: Duration,
}

impl Scanner {
    pub fn new(
        addresses: Vec<IpDomainPair>,
        blocklist: blocklist::Blocklist,
        rootstore: PathBuf,
        output_dir: PathBuf,
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
            output_dir,
            template_connector,
            destination_port: port,
            timeout,
        })
    }

    /// Starts the scan, consuming the scanner.
    pub fn start_scan(self) {
        for ipdomain in self.scanlist.iter() {
            self.scan(ipdomain);
        }
    }

    /// Performs the scan on the ip address in `IpDomainPair`
    fn scan(&self, addr: &IpDomainPair) -> ScanResult {
        // create tcp stream
        let stream = TcpStream::connect_timeout(
            &SocketAddr::new(addr.0.into(), self.destination_port),
            self.timeout,
        )
        .unwrap();

        let con = self.template_connector.clone();

        match con.connect(&addr.1.to_str(), stream) {
            Ok(s) => {
                println!("{:#?}", s)
            }
            Err(err) => {
                println!("{:#?}", err)
            }
        }
        todo!()
    }
}

#[derive(Serialize, Deserialize)]
struct ScanResult {
    tls_version: String,
    certificate_chain: String,
}
