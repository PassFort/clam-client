//! # clam_client - a client implementation for ClamAV written in Rust. 
//! `clam_client`, provides a simple interface to all basic ClamAV functionality, currently 
//! the only thing missing is sessions/multi threaded scanning, which may or may not be added
//! depending on demand.
//!
//! ## Example
//! ```rust
//! extern crate clam_client;
//! use clam_client::client::ClamClient;
//! use std::env;
//! 
//! fn main() {
//!     if let Some(path) = env::args().nth(1) {
//!         let client = ClamClient::new("127.0.0.1", 3310).unwrap();
//!         println!(
//!             "Scan for '{}':\n\t{:?}\n",
//!             path,
//!             client.scan_path(&path, true).unwrap()
//!         );
//!     } else {
//!         println!("USAGE: cargo run --example simple \"<file_path>\"");
//!     }
//! }
//! ```
//! 

#[macro_use]
extern crate failure;
#[macro_use]
extern crate nom;

extern crate byteorder;
extern crate chrono;

pub mod client;
pub mod error;
pub mod response;

#[cfg(test)]
mod tests {
    use chrono::prelude::*;
    use response;

    #[test]
    fn parse_version() {
        let raw = "ClamAV 0.100.0/24802/Wed Aug  1 08:43:37 2018".to_owned();
        let parsed = response::ClamVersion {
            version_tag: "ClamAV 0.100.0".to_owned(),
            build_number: 24802,
            release_date: Utc
                .datetime_from_str("Wed Aug  1 08:43:37 2018", "%a %b %e %T %Y")
                .unwrap(),
        };
        let result = response::ClamVersion::parse(raw).unwrap();

        assert_eq!(result.version_tag, parsed.version_tag);
        assert_eq!(result.build_number, parsed.build_number);
        assert_eq!(result.release_date, parsed.release_date);
    }
}
