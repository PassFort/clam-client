# clam-client

`clam-client` is a simple rust interface for talking to a ClamAV server over a TCP socket.

Example:

```rust
extern crate clam_client;

use clam_client::client::ClamClient;
use clam_client::response::ClamScanResult;

fn main() {
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

## Todo

- Add support for sessions: IDSESSION / END
- Decide whether to implement VERSIONCOMMANDS
- Decide whether to implement FILDES