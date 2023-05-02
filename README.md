# TLS Scanner written in Rust

## Description
TLS Scanner written in Rust, originally created for the course Empirical Security Analysis & Engineering (2022/2023)
at the University of Twente. It then turned into a project I extend to learn.

## Building
### Dependencies

* Rust (recommended to install via `rustup`).
* OpenSSL, see https://docs.rs/openssl/latest/openssl/#automatic for instructions.

## Usage
 Mandatory option:
 * `--ip-list`: csv file with a domain corresponding IP pair on each line: `<domain>,<ipv4>`
 * `--block-list`: list of ipv4 addresses or domains that will not be scanned.
 * `--root-store`: x509 root store to use.
 * `--output`: output file to store the results in, in JSON format.

 Run with `--help` to see all options.
