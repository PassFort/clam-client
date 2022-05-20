# clam-client

`clam-client` is a simple rust interface for talking to a ClamAV server over a TCP socket.

Forked from https://gitlab.com/AviateX14/clam-client as it seems unmaintained.

Example:

```rust
extern crate clam_client;

use clam_client::client::ClamClient;
use clam_client::response::ClamScanResult;

fn main() {
    let client = ClamClient::new("127.0.0.1", 3310).unwrap();

    if let Ok(results) = client.scan_path("/tmp/", true) {
        for scan_result in results.iter() {
            match scan_result {
                ClamScanResult::Found(location, virus) => {
                    println!("Found virus: '{}' in {}", virus, location)
                },
                _ => {}
            }
        }
    }
}
```

Streaming is also supported:

```rust
let client = ClamClient::new("127.0.0.1", 3310).unwrap();
let file = File::open(some_path).unwrap();

match client.scan_stream(file) {
    Ok(result) => match result {
        ClamScanResult::Ok => println!("File {} is OK!", some_path,
        ClamScanResult::Found(_, virus) => {
            println!("Found virus: '{}' in {}", virus, some_path)
        }
        ClamScanResult::Error(err) => println!("Received error from ClamAV: {}", err),
    },
    Err(e) => println!("A network error occurred whilst talking to ClamAV:\n{}", e),
}

```

## Todo

- Add support for sessions: IDSESSION / END
- Decide whether to implement VERSIONCOMMANDS
- Decide whether to implement FILDES
