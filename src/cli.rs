use clap::Parser;

/// TLS scanner for Emprical Security Analysis & Engineering implemented in Rust.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    /// List of IPv4 addresses to be scanned.
    ///
    /// The file should have one domain/ipv4 address pair per line in the following format: "<domain>,<ipv4>".
    #[clap(short, long, value_parser)]
    pub ip_list: String,

    /// Block list to use.
    ///
    /// Domains and ipv4 addresses in this file will not be scanned.
    /// The file should have one ipv4 address or domain per line.
    #[clap(short, long, value_parser)]
    pub block_list: String,

    /// Output file to write the results to in JSON.
    #[clap(short, long, value_parser)]
    pub output: String,

    /// Destination port
    #[clap(short, long, default_value_t = 443u16, value_parser)]
    pub port: u16,

    /// Print debug information.
    #[clap(short, long)]
    pub verbose: bool,

    /// X509 Root store to use.
    #[clap(short, long, value_parser)]
    pub root_store: String,

    /// Timeout for each connection in seconds.
    #[clap(short, long, value_parser, default_value_t = 10)]
    pub timeout: u64,

    /// Number of threads to use to perform the scan.
    #[clap(long, value_parser, default_value_t = 1)]
    pub threads: u64,
}
