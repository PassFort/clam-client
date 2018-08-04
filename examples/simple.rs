extern crate clam_client;

use clam_client::client::ClamClient;
use clam_client::response::ClamScanResult;
use std::env;

fn main() {
    if let Some(path) = env::args().nth(1) {
        let client = ClamClient::new("127.0.0.1", 3310).unwrap();
        println!("Scanning: {}", path);
        if let Ok(results) = client.scan_path(&path, true) {
            for result in results.iter() {
                match result {
                    ClamScanResult::Ok => println!("File {} is OK!", path),
                    ClamScanResult::Found(location, virus) => {
                        println!("Found virus: '{}' in {}", virus, location)
                    }
                    ClamScanResult::Error(err) => println!("Received error from ClamAV: {}", err),
                }
            }
        }
    } else {
        println!("USAGE: cargo run --example simple \"<file_path>\"");
    }
}
