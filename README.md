# TLS Scanner written in Rust

## Description
TLS Scanner written in Rust for the course Empirical Security Analysis & Engineering (2022/2023)
at the University of Twente.

## Building
### Dependecies

* Rust toolchain (recommended to install via `rustup`).
* OpenSSL, see https://docs.rs/openssl/latest/openssl/#automatic for instructions.

* Cargo (installed by `rustup`) is Rust's package manager. Cargo will take care of all the rust dependencies.

### How to build and run
Simply run `cargo build --release` and find the binary in the `/target` directory
 or run `cargo run --release -- <arguments>`.

## Usage
 Mandatory option:
 * `--ip-list`: csv file with a domain corresponding IP pair on each line: `<domain>,<ipv4>`
 * `--block-list`: list of ipv4 addresses or domains that will not be scanned.
 * `--root-store`: x509 root store to use.
 * `--output`: output file to store the results in, in JSON format.

 Run with `--help` to see all options.

## Code documentation
You can browse the source code, but you can also have a look at the (be it minimal) docs. Simply run `cargo doc --release --open` to generate docs and open it in the browser.
