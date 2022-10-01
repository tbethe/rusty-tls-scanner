use super::blocklist::Blocklist;
use super::IpDomainPair;

use std::vec::IntoIter;

pub struct Scanlist {
    blocklist: Blocklist,
    // ipv4 address, domain
    addresses: IntoIter<IpDomainPair>,
}

impl Scanlist {
    pub fn new(addresses: Vec<IpDomainPair>, blocklist: Blocklist) -> Self {
        Scanlist {
            blocklist,
            addresses: addresses.into_iter(),
        }
    }
}

impl Iterator for Scanlist {
    type Item = IpDomainPair;

    fn next(&mut self) -> Option<Self::Item> {
        let mut nxt = self.addresses.next()?;
        while self.blocklist.is_blocked_subnet(nxt.0) || self.blocklist.is_blocked_domain(&nxt.1) {
            nxt = self.addresses.next()?;
        }
        Some(nxt)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Domain {
    parts: Vec<String>,
}

impl Domain {
    // Checks if `self` is a subdomain of `other`.
    pub fn is_subdomain(&self, other: &Self) -> bool {
        // if the subdomain has less parts, it cannot be a subdomain
        if self.parts.len() < other.parts.len() {
            return false;
        }
        for (a, b) in std::iter::zip(self.parts.iter().rev(), other.parts.iter().rev()) {
            if a != b {
                return false;
            }
        }
        true
    }

    pub fn to_str(&self) -> String {
        self.parts.join(".")
    }
}

impl TryFrom<String> for Domain {
    type Error = &'static str;

    fn try_from(string: String) -> Result<Self, Self::Error> {
        let mut parts = Vec::new();
        for part in string.split('.') {
            if !part.is_empty() {
                parts.push(part.to_string())
            }
        }
        if parts.is_empty() {
            return Err("Domain is empty");
        }
        Ok(Domain { parts })
    }
}
#[cfg(test)]
mod tests {
    mod domain {
        use crate::scanner::Domain;

        // Returns a Domain for `domain`
        // panics if the domain is invalid.
        fn domain_from_str(domain: &str) -> Domain {
            Domain::try_from(domain.to_owned()).unwrap()
        }

        // returns a Domain for "sub.domain.com"
        fn domain() -> Domain {
            Domain::try_from("sub.domain.com".to_owned()).unwrap()
        }

        #[test]
        fn test_domain_equality() {
            assert_ne!(
                domain(),
                Domain {
                    parts: vec!("domain".to_string(), "sub".to_string(), "com".to_string())
                }
            );
        }

        #[test]
        fn test_try_from_failure_empty() {
            assert_eq!(Domain::try_from("".to_owned()), Err("Domain is empty"));
        }
        #[test]
        fn test_try_from_success() {
            assert_eq!(
                Domain::try_from("sub.domain.com".to_owned()).unwrap(),
                Domain {
                    parts: vec!("sub".to_string(), "domain".to_string(), "com".to_string())
                }
            );
        }

        #[test]
        fn test_try_from_success_many_dots() {
            assert_eq!(
                domain(),
                Domain {
                    parts: vec!("sub".to_string(), "domain".to_string(), "com".to_string())
                }
            );
        }

        #[test]
        fn test_try_from_success_starts_with_dots() {
            assert_eq!(
                domain(),
                Domain {
                    parts: vec!("sub".to_string(), "domain".to_string(), "com".to_string())
                }
            );
        }
        #[test]
        fn test_try_from_success_ends_with_dots() {
            assert_eq!(
                domain(),
                Domain {
                    parts: vec!("sub".to_string(), "domain".to_string(), "com".to_string())
                }
            );
        }

        #[test]
        fn is_subdomain_success() {
            assert!(
                domain_from_str("sub.example.com").is_subdomain(&domain_from_str("example.com"))
            );
        }

        #[test]
        fn is_subdomain_success_same_domain() {
            assert!(domain_from_str("example.com").is_subdomain(&domain_from_str("example.com")));
        }

        #[test]
        fn is_subdomain_failure() {
            assert!(
                !domain_from_str("example.com").is_subdomain(&domain_from_str("sub.example.com"))
            );
        }
    }
}
