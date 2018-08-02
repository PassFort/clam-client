extern crate clam_client;

use clam_client::client::ClamClient;

fn main() {
    let client = ClamClient::new("127.0.0.1", 3310).unwrap();
    println!("ClamD info:\n\t{:?}\n", client.version().unwrap());
    println!("ClamD stats:\n\t{:?}\n", client.stats().unwrap());
}