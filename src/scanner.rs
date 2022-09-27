mod blocklist;
mod ip_list;

pub use blocklist::Blocklist;
pub use ip_list::Domain;

use ip_list::Scanlist;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Debug)]
pub struct IpDomainPair(pub Ipv4Addr, pub Domain);

pub struct Scanner {
    scanlist: Scanlist,
    output_dir: PathBuf,
}

impl Scanner {
    pub fn new(
        addresses: Vec<IpDomainPair>,
        blocklist: blocklist::Blocklist,
        output_dir: PathBuf,
    ) -> Self {
        Scanner {
            scanlist: Scanlist::new(addresses, blocklist),
            output_dir,
        }
    }

    pub fn scan(self) {
        for ip in self.scanlist.into_iter() {
            println!("{:?}", ip);
        }
    }
}
