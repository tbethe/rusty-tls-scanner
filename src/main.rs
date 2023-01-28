//!# TLS Scanner written in Rust
//!
//!## Description
//!TLS Scanner written in Rust for the course Empirical Security Analysis & Engineering (2022/2023)
//!at the University of Twente.
//!
//!## Building
//!### Dependecies
//!
//!* Rust toolchain (recommended to install `rustup`).
//!* OpenSSL
//!
//!* Cargo, Rust's package manager, will take care of all the rust dependencies.
//!
//!### How to build
//!Simply run `cargo build --release` and find the binary in the `/target` directory
//! or run `cargo build --release -- <arguments>`.
//!
//!## Usage
//! Mandatory option:
//! * `--ip-list`: csv file with a domain corresponding IP pair on each line: `<domain>,<ipv4>`
//! * `--block-list`: list of ipv4 addresses or domains that will not be scanned.
//! * `--root-store`: x509 root store to use.
//! * `--output`: output file to store the results in.
//!
//! Run with `--help` to see all options.

mod cli;
mod ratelimiter;
mod scanner;

use anyhow::{bail, Context, Result};

use clap::Parser;
use log::{debug, info};
use std::{fs::read_to_string, net::Ipv4Addr, path::PathBuf, str::FromStr, time::Duration};

use scanner::Blocklist;
use scanner::Domain;

use crate::scanner::ScannerOpts;

/// Main function that creates the commandline interface and constructs
/// and runs the scanner.
fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    // Initialize logger
    let mut log_builder = env_logger::Builder::new();
    if cli.verbose {
        log_builder.filter_level(log::LevelFilter::Debug);
    }
    log_builder.init();

    // read and parse ip addresses to be scanned
    let path = PathBuf::from(&cli.ip_list);
    let ip_list = read_to_string(path).with_context(|| "Could not read ip_list")?;
    let addresses = ip_list
        .lines()
        .enumerate()
        .filter_map(|(l, s)| {
            let line = l + 1;
            let (domain, ip) = s.split_once(',').or_else(|| {
                debug!("Could not split ip and domain on line {}: {}", line, s);
                None
            })?;
            let domain = Domain::try_from(domain).ok().or_else(|| {
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
    let block_list = read_to_string(path).with_context(|| "Failed to read the blocklist")?;
    let blocklist: Blocklist = Blocklist::new(block_list.lines().collect::<Vec<_>>().as_slice());

    // check that the output file is not a directory
    let output_path = PathBuf::from(&cli.output);
    if output_path.is_dir() {
        bail!("Output path is a directory.")
    }

    let rootstore_path = PathBuf::from(&cli.root_store);

    // finally construct the scanner
    debug!("Constructing the scanner.");
    let scanner_options = ScannerOpts::new(
        cli.port,
        Duration::from_secs(cli.timeout),
        cli.threads,
        Duration::from_millis(cli.rate),
    );
    let scanner = scanner::Scanner::new(
        addresses,
        blocklist,
        output_path,
        rootstore_path,
        scanner_options,
    )
    .with_context(|| "Could not construct the scanner")?;
    info!("Starting the scan.");
    scanner.start_scan()?;
    info!("Successfully completed the scan.");
    Ok(())
}
