extern crate clam_client;

use clam_client::client::ClamClient;
use std::env;

fn main() {
    if let Some(path) = env::args().nth(1) {
        let client = ClamClient::new("127.0.0.1", 3310).unwrap();
        println!("Scan for '{}':\n\t{:?}\n", path, client.scan_path(&path, true).unwrap());
    } else {
        println!("USAGE: cargo run --example simple \"<file_path>\"");
    }
}