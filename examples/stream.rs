extern crate clam_client;

use clam_client::client::ClamClient;
use clam_client::response::ClamScanResult;
use std::env;
use std::fs::File;

fn main() {
    if let Some(path) = env::args().nth(1) {
        let client = ClamClient::new("127.0.0.1", 3310).unwrap();
        let file = File::open(&path).unwrap();

        match client.scan_stream(file) {
            Ok(result) => match result {
                ClamScanResult::Ok => println!("File {} is OK!", path),
                ClamScanResult::Found(location, virus) => {
                    println!("Found virus: '{}' in {}", virus, location)
                }
                ClamScanResult::Error(err) => println!("Received error from ClamAV: {}", err),
            },
            Err(e) => println!("A network error occurred whilst talking to ClamAV:\n{}", e),
        }
    } else {
        println!("USAGE: cargo run --example stream \"<file_path>\"");
    }
}
