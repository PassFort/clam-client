extern crate clam_client;

use clam_client::client::ClamClient;
use std::fs::File;

fn main() {
    let client = ClamClient::new("127.0.0.1", 3310).unwrap();
    let file = File::open("/Users/joe/Downloads/eicar.com").unwrap();
    println!("{:?}", client.scan_stream(file));
}