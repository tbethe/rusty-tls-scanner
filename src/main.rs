mod _playground;
mod scanner;

use scanner::Domain;
use serde::Serialize;

use std::{
    fs::{read_to_string, write},
    net::Ipv4Addr,
    path::PathBuf,
    process::{exit, Output},
    str::FromStr,
    time::Duration,
};

use clap::Parser;
use log::{debug, error, info};

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

    /// Output file
    #[clap(short, long, value_parser)]
    output: String,

    /// Destination port
    #[clap(short, long, default_value_t = 443u16, value_parser)]
    port: u16,

    /// Verbosity
    #[clap(short, long)]
    verbose: bool,

    /// Root store to use
    #[clap(short, long, value_parser)]
    root_store: String,

    /// Timeout for each separate connection in seconds
    #[clap(short, long, value_parser, default_value_t = 10)]
    timeout: u64,
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

    // output file
    let output_path = PathBuf::from(&cli.output);
    if output_path.is_dir() {
        error!("Output path is a directory.");
        exit(1)
    }
    if output_path.exists() {
        info!("Output file already exists and will be overwritten.");
    }
    let output_path_str = output_path.to_str().unwrap_or_else(|| {
        error!("output_path is not valid utf-8");
        exit(1);
    });

    let rootstore_path = PathBuf::from(&cli.root_store);

    // finally construct the scanner
    let scanner = scanner::Scanner::new(
        addresses,
        blocklist,
        rootstore_path,
        cli.port,
        Duration::from_secs(cli.timeout),
    )
    .unwrap_or_else(|e| {
        error!("Could not construct the scanner: {}", e);
        exit(1);
    });
    let scan_results = scanner.start_scan();

    let json = serde_json::to_string_pretty(&scan_results).unwrap_or_else(|e| {
        error!("Could not serialize the results to JSON: {}", e.to_string());
        exit(1);
    });
    write(output_path_str, &json).unwrap_or_else(|_| {
        error!(
            "Failed to write results to file '{}'. Error: {}",
            output_path_str, &json
        );
        exit(1);
    });
    debug!("Done. Results have been written to {}", output_path_str);
}
