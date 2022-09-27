mod scanner;

use scanner::Domain;

use std::{fs::read_to_string, net::Ipv4Addr, path::PathBuf, process::exit, str::FromStr};

use clap::Parser;
use log::{debug, error};

use crate::scanner::Blocklist;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// List of IPv4 addresses to be scanned
    #[clap(short, long, value_parser)]
    ip_list: String,

    /// Use a different block list
    #[clap(short, long, value_parser)]
    block_list: String,

    /// Output directory
    #[clap(short, long, value_parser)]
    output_dir: String,

    /// Destination port
    #[clap(short, long, default_value_t = 443u16, value_parser)]
    port: u16,

    /// Verbosity
    #[clap(short, long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    // Initialize logger
    let mut log_builder = env_logger::Builder::new();
    if cli.verbose {
        log_builder.filter_level(log::LevelFilter::Debug);
    }
    log_builder.init();

    // warning examples.
    //error!("This is an error");
    //debug!("This is a debug statement");

    // read and parse ip addresses to be scanned
    let path = PathBuf::from(&cli.ip_list);
    let ip_list = read_to_string(path).unwrap_or_else(|e| {
        error!("Could not read `ip_list`: {}", e.to_string());
        exit(1);
    });
    let addresses: Vec<_> = ip_list
        .lines()
        .enumerate()
        .filter_map(|(l, s)| {
            let line = l + 1;
            let (domain, ip) = s.split_once(',').or_else(|| {
                debug!("Could not split ip and domain on line {}: {}", line, s);
                None
            })?;
            let domain = Domain::try_from(domain.to_string()).ok().or_else(|| {
                debug!("Could not parse domain on line {}: {}", line, domain);
                None
            })?;
            let ip = Ipv4Addr::from_str(ip).ok().or_else(|| {
                debug!("Could not parse IP on line {}: {}", line, ip);
                None
            })?;
            Some(scanner::IpDomainPair(ip, domain))
        })
        .collect();

    // read and parse the blocklist
    let path = PathBuf::from(&cli.block_list);
    let block_list = read_to_string(path).unwrap_or_else(|e| {
        error!("Could not read `block_list`: {}", e.to_string());
        exit(1);
    });
    let blocklist: Blocklist = Blocklist::new(block_list.lines().map(|s| s.to_string()).collect());

    // output directory
    let output_path = PathBuf::from(&cli.output_dir);

    let scanner = scanner::Scanner::new(addresses, blocklist, output_path);
    scanner.scan();

    println!("{:#?}", cli);
}
