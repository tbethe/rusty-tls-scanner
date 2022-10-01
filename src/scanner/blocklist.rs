//! Implementation of the blocklist in [`Blocklist`]
//!
//! This blocklist is a list of IPv4 addresses and domains which should be blocked.
//! This enables you to check if a given address or domain is blocked.
//!
//! Subdomains of a blocked domain are also blocked.

use log::debug;
use std::{net::Ipv4Addr, str::FromStr};

use super::Domain;

/// This blocklist is a list of IPv4 addresses and domains which should be blocked.
/// This enables you to check if a given address or domain is blocked.
///
/// Subdomains of a blocked domain are also blocked.
pub struct Blocklist {
    domains: Vec<Domain>,
    subnets: Vec<Subnet>,
}

impl Blocklist {
    /// Creates a blocklist of a list of strings. The strings can be domains and IPv4 addresses
    /// interspersed. This implementation simply assumes that strings with '/' inside are subnets, other strings are domains.
    /// Creation of the blocklist always succeeds. Bad strings (invalid IPv4 addresses or invalid
    /// domains) are simply excluded from the list. However, a debug message is sent whenever a
    /// string could not be parsed.
    pub fn new(block_list: Vec<String>) -> Self {
        let mut domains = Vec::new();
        let mut subnets = Vec::new();
        for s in block_list {
            if s.contains('/') {
                // subnet
                match Subnet::try_from(s.to_owned()) {
                    Ok(subnet) => subnets.push(subnet),
                    Err(err) => debug!("Failed to add {} during blocklist creation: {}", s, err),
                }
            } else {
                // domain
                match Domain::try_from(s.to_owned()) {
                    Ok(domain) => domains.push(domain),
                    // library functions shouldn't use loggers TODO
                    Err(err) => debug!("Failed to add {} during blocklist creation: {}", s, err),
                }
            }
        }
        Blocklist { domains, subnets }
    }

    /// Checks if `ip` is blocked by this blocklist.
    pub fn is_blocked_subnet(&self, ip: Ipv4Addr) -> bool {
        for subnet in &self.subnets {
            if subnet.ip_in_subnet(ip) {
                return true;
            }
        }
        false
    }

    /// Checks if `domain` is blocked by this blocklist.
    ///
    /// If `domain` is a _subdomain_ of a domain in the blocklist, `domain` will still be bocked,
    /// i.e., this function will return `true`.
    pub fn is_blocked_domain(&self, domain: &Domain) -> bool {
        for domain_s in &self.domains {
            if domain_s.is_subdomain(domain) {
                return true;
            }
        }
        false
    }
}

#[derive(Debug)]
struct Subnet {
    ip: u32,
    mask: u32,
}

impl Subnet {
    /// Checks if `ip` is in the subnet that `Self` represents.
    /// Returns `true` if `ip` belongs to `Self`s subnet, `false` otherwise.
    fn ip_in_subnet(&self, ip: Ipv4Addr) -> bool {
        let _ip: u32 = ip.into();
        _ip & self.mask == self.ip & self.mask
    }
}

impl TryFrom<String> for Subnet {
    type Error = &'static str;

    fn try_from(string: String) -> Result<Self, Self::Error> {
        let (ip, subnet) = string
            .split_once('/')
            .ok_or("Invalid subnet notation: No '/' found")?;
        // parse ip address
        let ip: u32 = Ipv4Addr::from_str(ip)
            .map_err(|_| "Could not parse IP.")?
            .into();
        // parse mask
        let subnet: u32 = subnet.parse().map_err(|_| "Subnet is not a number.")?;
        if subnet > 32 {
            return Err("Subnet cannot be larger than 32");
        }

        let mask: u32 = if subnet == 0 {
            0
        } else {
            u32::MAX << (32 - subnet)
        };
        Ok(Subnet { ip, mask })
    }
}

#[cfg(test)]
mod tests {
    mod blocklist {
        use std::{net::Ipv4Addr, str::FromStr};

        use crate::scanner::{blocklist::Blocklist, Domain};

        // Create blocklist from the first few lines of the blocklist given in the assignment.
        fn create_blocklist() -> Blocklist {
            let list = vec![
                "audioengineering.com",
                "142.239.0.0/16",
                "128.173.8.0/22",
                "165.11.0.0/16",
                "129.247.81.0/24",
                "psamathe.net",
                "batmanov.de",
                "46.30.240.0/22",
                "128.95.188.0/24",
                "149.162.208.0/20",
                "maureencooke.com",
                "127.0.0.0/8",
                "156.67.211.154/32",
                "193.25.170.0/23",
                "maureenfcooke.com",
                "208.81.245.240/29",
                "212.71.252.215/32",
                "149.165.246.0/24",
                "boshandmurphy.com",
                "157.7.32.53/32",
                "197.242.84.0/22",
                "65.21.56.69/32",
                "186.193.238.86/32",
                "213.239.192.0/18",
                "buscharter.com.au",
            ];
            let list = list.into_iter().map(|s| s.to_owned()).collect();
            Blocklist::new(list)
        }

        #[test]
        fn test_subnet_in_blocklist() {
            let bl = create_blocklist();
            assert!(bl.is_blocked_subnet(Ipv4Addr::from_str("186.193.238.86").unwrap()));
            assert!(bl.is_blocked_subnet(Ipv4Addr::from_str("213.239.200.0").unwrap()));
            assert!(bl.is_blocked_subnet(Ipv4Addr::from_str("208.81.245.241").unwrap()));
            assert!(bl.is_blocked_subnet(Ipv4Addr::from_str("127.0.0.1").unwrap()));

            assert!(!bl.is_blocked_subnet(Ipv4Addr::from_str("186.193.238.85").unwrap()));
            assert!(!bl.is_blocked_subnet(Ipv4Addr::from_str("126.120.120.123").unwrap()));
        }

        #[test]
        fn test_domain_in_blocklist() {
            let bl = create_blocklist();
            assert!(
                bl.is_blocked_domain(&Domain::try_from("buscharter.com.au".to_owned()).unwrap())
            );
            assert!(
                bl.is_blocked_domain(&Domain::try_from("boshandmurphy.com".to_owned()).unwrap())
            );
            assert!(bl.is_blocked_domain(&Domain::try_from("psamathe.net".to_owned()).unwrap()));
            assert!(
                bl.is_blocked_domain(&Domain::try_from("audioengineering.com".to_owned()).unwrap())
            );
        }
    }
    mod subnet {
        use std::{net::Ipv4Addr, str::FromStr};

        use crate::scanner::blocklist::Subnet;

        fn test_ip_in_subnet(subnet: &str, ip: &str) -> bool {
            // can panic, but if it panics here, the test is written wrong.
            let ip = Ipv4Addr::from_str(ip).unwrap();
            Subnet::try_from(subnet.to_owned())
                .unwrap()
                .ip_in_subnet(ip)
        }

        #[test]
        fn valid() {
            Subnet::try_from("1.1.1.1/24".to_owned()).unwrap();
        }

        #[test]
        fn valid_32_subnet() {
            Subnet::try_from("1.1.1.1/32".to_owned()).unwrap();
        }

        #[test]
        fn valid_0_subnet() {
            Subnet::try_from("192.168.192.4/0".to_owned()).unwrap();
        }
        #[test]
        #[should_panic]
        fn invalid_subnet() {
            Subnet::try_from("1.1.1.1/50".to_owned()).unwrap();
        }

        #[test]
        #[should_panic]
        fn invalid_ip() {
            Subnet::try_from("500.1.1.1/23".to_owned()).unwrap();
        }

        #[test]
        #[should_panic]
        fn invalid_ip2() {
            Subnet::try_from("500.as.1.1/23".to_owned()).unwrap();
        }

        #[test]
        #[should_panic]
        fn invalid_ip3() {
            Subnet::try_from("example.com/16".to_owned()).unwrap();
        }

        #[test]
        fn test_in_subnet() {
            assert!(test_ip_in_subnet("1.1.1.1/16", "1.1.153.123"));
            assert!(test_ip_in_subnet("1.1.1.1/32", "1.1.1.1"));
            assert!(test_ip_in_subnet("186.193.238.86/32", "186.193.238.86"));
            assert!(test_ip_in_subnet("192.195.132.74/32", "192.195.132.74"));
            assert!(test_ip_in_subnet("1.1.1.1/0", "100.1.153.123"));
            assert!(test_ip_in_subnet("1.1.1.1/15", "1.1.153.123"));
            assert!(test_ip_in_subnet("1.1.1.1/24", "1.1.1.123"));

            assert!(!test_ip_in_subnet("1.1.1.1/16", "10.1.153.123"));
            assert!(!test_ip_in_subnet("1.1.1.1/31", "1.1.153.123"));
        }
    }
}
