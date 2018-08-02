extern crate clam_client;

use clam_client::client::ClamClient;
use std::fs::File;
use std::env;

fn main() {
    if let Some(path) = env::args().nth(1) {
        let client = ClamClient::new("127.0.0.1", 3310).unwrap();
        let file = File::open(&path).unwrap();

        println!("Scan for '{}':\n\t{:?}\n", path, client.scan_stream(file).unwrap());
    } else {
        println!("USAGE: cargo run --example stream \"<file_path>\"");
    }
}