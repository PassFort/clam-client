#![deny(missing_docs)]

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

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[macro_use]
extern crate failure;
#[macro_use]
extern crate nom;

extern crate byteorder;
extern crate chrono;

pub mod client;
pub mod error;
pub mod response;
