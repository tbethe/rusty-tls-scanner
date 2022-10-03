//! Module responsible for performing the actual scan
//!
//! The struct [Scanner] does the heavy lifting.

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
use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Abstraction over a pair of an IPv4 address and a domain,
/// just like we expect a line of the input file to look like.
#[derive(Debug)]
pub struct IpDomainPair(pub Ipv4Addr, pub Domain);

/// TLS Scanner that actually performs the scan.
pub struct Scanner {
    scanlist: Scanlist,
    /// This connector will be configured once when the scanner is initialized and will serve as a
    /// template for all the TLS connections that the this scanner will create.
    template_connector: SslConnector,
    output_path: PathBuf,
    destination_port: u16,
    timeout: Duration,
    threads: u64,
}

impl Scanner {
    /// Constructs a new scanner.
    ///
    /// # Error
    /// Returns `Err(String)` if something went wrong loading the x509 root store.
    pub fn new(
        addresses: Vec<IpDomainPair>,
        blocklist: blocklist::Blocklist,
        output_path: PathBuf,
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
            output_path,
            destination_port: port,
            timeout,
            threads,
        })
    }

    /// Starts the scan, consuming the scanner.
    ///
    /// The scan results will be written to a file indicated by `self.output_path`.
    pub fn start_scan(self) {
        // scan list for all thread to pull the next ip from
        let scan_list = Arc::new(Mutex::new(self.scanlist));
        // collection channel to put the gathered tls info into
        let (res_sender, res_receiver) = std::sync::mpsc::channel();

        // spawn the producers, a.k.a. the threads that will perform the scans.
        let mut handles = Vec::new();
        for _ in 0..self.threads {
            let timeout = self.timeout;
            let port = self.destination_port;
            let sl = Arc::clone(&scan_list);
            let res = res_sender.clone();
            let con = self.template_connector.clone();

            handles.push(thread::spawn(move || {
                loop {
                    let mut guard = sl.lock().unwrap();
                    let ipdomain = match guard.next() {
                        Some(a) => a,
                        None => {
                            break;
                        }
                    };
                    // let go of the lock as soon as possible.
                    std::mem::drop(guard);

                    let connector = con.clone();
                    let tls_info = Scanner::scan(&ipdomain, port, connector, timeout);

                    res.send(tls_info);
                }
            }));
        }

        // spawn the consumer that writes to file.
        let still_producing = Arc::new(Mutex::new(true));
        let still_producing_t = still_producing.clone();
        let consumer_handle = thread::spawn(move || {
            let mut out = File::create(self.output_path).unwrap();
            // open the JSON array
            out.write(b"[\n");
            let mut first = true;
            loop {
                let tls_info = match res_receiver.try_recv() {
                    Ok(a) => a,
                    Err(_) => {
                        // error means the channel was empty
                        // if the channel is empty, but we are still producing,
                        // continue the loop
                        // otherwise, we are done and no new entries will appear,
                        // so we break
                        if *still_producing_t.lock().unwrap() {
                            continue;
                        } else {
                            break;
                        }
                    }
                };

                // except for the first entry, prepend the comma to satisfy JSON format
                if !first {
                    out.write(b",\n");
                } else {
                    first = false;
                }
                // convert to JSON
                let json = serde_json::to_string_pretty(&tls_info).unwrap();
                out.write(&json.into_bytes());
            }
            // close the JSON array
            out.write(b"]");
        });

        // wait for all the producer threads to finish
        for (n, h) in handles.into_iter().enumerate() {
            h.join().unwrap();
        }
        debug!("All producer threads finished.");
        // Make sure the guard is dropped immediately so the producer thread
        // can acquire the lock
        {
            *still_producing.lock().unwrap() = false;
        }
        consumer_handle.join().unwrap();
        debug!("Scan completed.");
    }

    /// Performs the scan on the ip address in `IpDomainPair`
    fn scan(
        addr: &IpDomainPair,
        port: u16,
        connector: SslConnector,
        timeout: Duration,
    ) -> ConnectionInfo {
        // try to connect a TCP stream. Fail after a certain timeout
        let stream =
            match TcpStream::connect_timeout(&SocketAddr::new(addr.0.into(), port), timeout) {
                Ok(s) => s,
                Err(err) => return ConnectionInfo::from_tcp_stream_err(addr, err.to_string()),
            };

        // to avoid hanging on TLS handshake, set read timeout.
        // unwrapping is safe, because the call only returns as error if duration=0 is passed in
        stream
            .set_read_timeout(Some(timeout))
            .expect("Duration cannot be 0");

        match connector.connect(&addr.1.to_string(), stream) {
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

//
// Objects to facilitate serializing the TLS info
//

/// Struct that represents the result of scanning 1 ip/domain.
#[derive(Serialize, Deserialize, Debug)]
struct ConnectionInfo {
    domain: String,
    ip_address: String,
    connection_failure: bool,
    connection_failure_reason: Option<String>,
    tls_connection_info: Option<TLSConnectionInfo>,
}

impl ConnectionInfo {
    /// Creates a `ConnectionInfo` from when the TCP stream errored, most likely
    /// because of a connection timeout
    fn from_tcp_stream_err(ipdomain: &IpDomainPair, reason: String) -> Self {
        let domain = ipdomain.1.to_string();
        let ip_address = ipdomain.0.to_string();
        ConnectionInfo {
            domain,
            ip_address,
            connection_failure: true,
            connection_failure_reason: Some(reason),
            tls_connection_info: None,
        }
    }

    /// Creates a `ConnectionInfo` with `tls_info`, meaning a handshake was at least attempted.
    fn from_tls_info(ipdomain: &IpDomainPair, tls_info: TLSConnectionInfo) -> Self {
        let domain = ipdomain.1.to_string();
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

/// Serializable info about the TLS connection
#[derive(Serialize, Deserialize, Debug)]
struct TLSConnectionInfo {
    state: String,
    state_long: String,
    handshake_failure_reason: Option<String>,
    tls_version: String,
    verify_result: String,
    verify_result_err: String,
    certificate_chain: Option<CertificateChain>,
}

impl TLSConnectionInfo {
    /// Extracts info from the [`SslStream`] to create the [`TLSConnectionInfo`].
    fn from_ssl_stream(s: SslStream<TcpStream>) -> Self {
        let ssl = s.ssl();

        TLSConnectionInfo {
            state: ssl.state_string().to_string(),
            state_long: ssl.state_string_long().to_string(),
            handshake_failure_reason: None,
            tls_version: ssl.version_str().to_string(),
            verify_result: ssl.verify_result().to_string(),
            verify_result_err: ssl.verify_result().error_string().to_string(),
            certificate_chain: Self::certificatechain_from_x509_stack(ssl.verified_chain()),
        }
    }

    /// Extracts info from the [`MidHandshakeSslStream`] to create the [`TLSConnectionInfo`].
    fn from_midhandshake_ssl_stream(s: MidHandshakeSslStream<TcpStream>) -> Self {
        let ssl = s.ssl();
        TLSConnectionInfo {
            state: ssl.state_string().to_string(),
            state_long: ssl.state_string_long().to_string(),
            handshake_failure_reason: Some(s.error().to_string()),
            tls_version: ssl.version_str().to_string(),
            verify_result: ssl.verify_result().to_string(),
            verify_result_err: ssl.verify_result().error_string().to_string(),
            certificate_chain: Self::certificatechain_from_x509_stack(ssl.verified_chain()),
        }
    }

    /// Helper function to create a [`CertificateChain`], an object we can serialize, from the OpenSSL objects.
    fn certificatechain_from_x509_stack(
        chain: Option<&StackRef<X509>>,
    ) -> Option<CertificateChain> {
        let mut chain_vec = Vec::new();

        for cert in chain? {
            chain_vec.push(Certificate::from_x509(cert));
        }
        Some(CertificateChain { chain: chain_vec })
    }
}

/// Chain of X509 Certificates.
/// The last cert in the chain is the root cert.
#[derive(Serialize, Deserialize, Debug)]
struct CertificateChain {
    chain: Vec<Certificate>,
}

/// Serializable version of an OpenSSL X509 Certificate.
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
