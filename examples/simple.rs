extern crate clam_client;

use clam_client::client::ClamClient;

fn main() {
    let client = ClamClient::new("127.0.0.1", 3310).unwrap();
    println!("ClamD info:\n\t{:?}\n", client.version().unwrap());
    println!("ClamD stats:\n\t{:?}\n", client.stats().unwrap());
    println!("Scan for '/home/':\n\t{}\n", client.scan_path("/home/", true).unwrap());
    println!("Scan for '/bin/ls':\n\t{}\n", client.scan_path("/bin/ls", true).unwrap());
    println!("Scan for '/doesnt/exist:\n\t{}\n", client.scan_path("/doesnt/exist", false).unwrap());
}