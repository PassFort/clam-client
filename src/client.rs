//! `ClamClient` provides the bridge between the Rust code and the ClamD socket, and implements
//! most Clam commands in a Rust idiomatic interface.

use crate::error::ClamError;
use crate::response::{ClamScanResult, ClamStats, ClamVersion};
use std::io::{BufReader, Read, Write};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

/// `ClamResult` is a simple wrapper used for all operations, this makes it simple to handle
/// from the callers side.
pub type ClamResult<T> = Result<T, ClamError>;

/// `ClamClient` is the crux of the crate, it retains information about what socket to connect
/// to, thus that it can reconnect, and what timeout (if any) to use when connecting.
///
/// *Note:* Future versions may move `timeout` to be use in command operations as well as
/// when connecting. However since the latter is so variable, this may require a different - or even
/// per call - timeout value.
pub struct ClamClient {
    socket: SocketAddr,
    timeout: Option<Duration>,
}

impl ClamClient {
    /// Creates a new instance of `ClamClient` with no connect timeout, commands issued from this
    /// client will indefinitely block if ClamD becomes unavailable.
    ///
    /// *Arguments*
    ///
    /// - `ip`: The IP address to connect to
    /// - `port`: The port to connect to
    ///
    /// *Example*
    ///
    /// ```rust
    /// extern crate clam_client;
    ///
    /// use clam_client::client::ClamClient;
    ///
    /// fn main() {
    ///     if let Ok(client) = ClamClient::new("127.0.0.1", 3310) {
    ///         println!("{:?}", client.version());
    ///     }
    /// }
    /// ```
    pub fn new(ip: &str, port: u16) -> ClamResult<ClamClient> {
        build(ip, port, None)
    }

    /// Creates a new instance of `ClamClient` with a connection timeout (in seconds). Any command
    /// issued from this client will error after `timeout_secs` if ClamD is unavailable.
    ///
    /// *Arguments*
    ///
    /// - `ip`: The IP address to connect to
    /// - `port`: The port to connect to
    /// - `timeout_secs`: The number of seconds to wait before aborting the connection
    ///
    /// *Example*
    ///
    /// ```rust
    /// extern crate clam_client;
    ///
    /// use clam_client::client::ClamClient;
    ///
    /// fn main() {
    ///     if let Ok(client) = ClamClient::new_with_timeout("127.0.0.1", 3310, 10) {
    ///         println!("{:?}", client.version());
    ///     }
    /// }
    /// ```
    pub fn new_with_timeout(ip: &str, port: u16, timeout_secs: u64) -> ClamResult<ClamClient> {
        build(ip, port, Some(Duration::from_secs(timeout_secs)))
    }

    /// Implements the ClamD `PING` command, returns true if ClamD responds with `PONG`, or false if
    /// there was an error, or ClamD did not respond with `PONG`.
    pub fn ping(&self) -> bool {
        match self.send_command(b"zPING\0") {
            Ok(resp) => resp == "PONG",
            Err(_) => false,
        }
    }

    /// Implements the ClamD `VERSION` conmand, returns a struct of `ClamVersion` if successful,
    /// or an error if processing the respnose failed, or if there was an issue talking to ClamD.
    pub fn version(&self) -> ClamResult<ClamVersion> {
        let resp = self.send_command(b"zVERSION\0")?;
        ClamVersion::parse(resp)
    }

    /// Implements the ClamD `RELOAD` command, returns the state of the request as a `String` from
    /// ClamD, or a network error if the command failed.
    pub fn reload(&self) -> ClamResult<String> {
        self.send_command(b"zRELOAD\0")
    }

    /// Implements the ClamD `SCAN` and `CONTSCAN` commands, returns a `Vec<ClamScanResult>` if the command
    /// was successful, or a network error if the command failed.
    ///
    /// *Arguments:*
    ///
    /// - `path`: The path to scan, this is a path that is on the ClamD server, or that it has access to.
    /// - `continue_on_virus`: If true, instructs ClamD to continue scanning even after it detects a virus.
    ///
    /// *Example*
    ///
    /// ```rust
    /// extern crate clam_client;
    ///
    /// use clam_client::client::ClamClient;
    /// use clam_client::response::ClamScanResult;
    ///
    /// fn main() {
    ///     let client = ClamClient::new("127.0.0.1", 3310).unwrap();
    ///
    ///     if let Ok(scan_results) = client.scan_path("/tmp/", true){
    ///         for result in scan_results.iter() {
    ///             match result {
    ///                 ClamScanResult::Found(location, virus) => {
    ///                     println!("Found virus: '{}' in {}", virus, location)
    ///                 },
    ///                 _ => {},
    ///             }
    ///         }
    ///     }
    /// }
    /// ```
    pub fn scan_path(
        &self,
        path: &str,
        continue_on_virus: bool,
    ) -> ClamResult<Vec<ClamScanResult>> {
        let result = if continue_on_virus {
            self.send_command(&format!("zCONTSCAN {}\0", path).into_bytes())?
        } else {
            self.send_command(&format!("zSCAN {}\0", path).into_bytes())?
        };

        Ok(ClamScanResult::parse(result))
    }

    /// Implements the ClamD `MULTISCAN` command which allows the ClamD instance to perform
    /// multi-threaded scanning. Returns a `Vec<ClamScanResult>` if the command wassuccessful,
    /// or a network error if the command failed.
    pub fn multiscan_path(&self, path: &str) -> ClamResult<Vec<ClamScanResult>> {
        let result = self.send_command(&format!("zSCAN {}\0", path).into_bytes())?;
        Ok(ClamScanResult::parse(result))
    }

    /// Implements the ClamD `INSTREAM` command, which allows the caller to stream a file to the ClamD
    /// instance. Retuns a `ClamScanResult` if the command was successful.
    ///
    /// *Arguments*:
    ///
    /// - `stream`: The object to be scanned, this must implement `Read`, it will be read into a buffer
    /// of 4096 bytes and then written to the ClamD instance. This object must not exceed the ClamD
    /// max stream size, else the socket will be forcibly closed - in which case an error will be reutned
    /// from this function.
    ///
    /// *Example*
    ///
    /// ```rust
    /// extern crate clam_client;
    ///
    /// use clam_client::client::ClamClient;
    /// use clam_client::response::ClamScanResult;
    /// use std::fs::File;
    ///
    /// fn main() {
    ///     let client = ClamClient::new("127.0.0.1", 3310).unwrap();
    ///     let file = File::open("/etc/hosts").unwrap();
    ///
    ///     match client.scan_stream(file) {
    ///         Ok(result) => match result {
    ///             ClamScanResult::Ok => println!("File /etc/hostname is OK!"),
    ///             ClamScanResult::Found(location, virus) => {
    ///                 println!("Found virus: '{}' in {}", virus, location)
    ///             },
    ///             ClamScanResult::Error(err) => println!("Received error from ClamAV: {}", err),
    ///         },
    ///         Err(e) => println!("A network error occurred whilst talking to ClamAV:\n{}", e),
    ///     }
    /// }
    /// ```
    pub fn scan_stream<T: Read>(&self, stream: T) -> ClamResult<ClamScanResult> {
        let mut reader = BufReader::new(stream);
        let mut buffer = [0; 4096];
        let mut connection = self.connect()?;

        self.connection_write(&connection, b"zINSTREAM\0")?;

        while let Ok(bytes_read) = reader.read(&mut buffer) {
            if bytes_read > u32::MAX as usize {
                return Err(ClamError::InvalidDataLengthError(bytes_read));
            }

            // Make sure to pad `bytes_read` to 4 bytes (regardless of architecture) for the chunk header
            self.connection_write(&connection, &(bytes_read as u64).to_be_bytes())?;
            self.connection_write(&connection, &buffer)?;

            if bytes_read < 4096 {
                break;
            }
        }

        self.connection_write(&connection, &[0, 0, 0, 0])?;

        let mut result = String::new();
        match connection.read_to_string(&mut result) {
            Ok(_) => {
                let scan_result = ClamScanResult::parse(&result);

                if let Some(singular) = scan_result.first() {
                    Ok(singular.clone())
                } else {
                    Err(ClamError::InvalidData(result))
                }
            }
            Err(e) => Err(ClamError::ConnectionError(e)),
        }
    }

    /// Implements the ClamD `STATS` command, and returns a struct of `ClamStats`.
    pub fn stats(&self) -> ClamResult<ClamStats> {
        let resp: String = self.send_command(b"zSTATS\0")?;
        ClamStats::parse(&resp)
    }

    /// Implements the ClamD `SHUTDOWN` command, and returns the status message - if any -
    /// from ClamD.
    ///
    /// *Note*: Since this shuts down the ClamD instance, it will ensure all future calls to
    /// this or any other `ClamClient` return errors, as such, thus function consumes the calling client.
    pub fn shutdown(self) -> ClamResult<String> {
        self.send_command(b"zSHUTDOWN\0")
    }

    /// Simple reusable wrapper function to send a basic command to the ClamD instance and obtain
    /// a `ClamResult` that can propogate up the error chain. This is responsible for creating,
    /// writing to, and managing the connection in all 'one-shot' operations.
    ///
    /// *Arguments*:
    ///
    /// - `command`: The command to issue in byte form.
    fn send_command(&self, command: &[u8]) -> ClamResult<String> {
        let mut connection = self.connect()?;

        match connection.write_all(command) {
            Ok(_) => {
                let mut result = String::new();
                match connection.read_to_string(&mut result) {
                    Ok(_) => Ok(result),
                    Err(e) => Err(ClamError::CommandError(e)),
                }
            }
            Err(e) => Err(ClamError::CommandError(e)),
        }
    }

    /// Simple reusable wrapper function for writing a byte stream to an established connection,
    /// returns the lengh of the data written if successful. This is especially useful for writing
    /// file streams.
    ///  
    /// *Arguments*:
    ///
    /// - `connection`: The established connection to write to.
    /// - `data`: The byte stream to send.
    fn connection_write(&self, mut connection: &TcpStream, data: &[u8]) -> ClamResult<usize> {
        match connection.write(data) {
            Ok(v) => Ok(v),
            Err(e) => Err(ClamError::CommandError(e)),
        }
    }

    /// Simple helper function to create a new connection to the ClamD socket.
    fn connect(&self) -> ClamResult<TcpStream> {
        let connection = if let Some(t) = self.timeout {
            TcpStream::connect_timeout(&self.socket, t)
        } else {
            TcpStream::connect(&self.socket)
        };

        match connection {
            Ok(handle) => Ok(handle),
            Err(e) => Err(ClamError::ConnectionError(e)),
        }
    }
}

/// Creates a new instance of `ClamClient`.
fn build(ip: &str, port: u16, timeout: Option<Duration>) -> ClamResult<ClamClient> {
    let addr: IpAddr = match ip.parse() {
        Ok(v) => v,
        Err(e) => return Err(ClamError::InvalidIpAddress(e)),
    };

    let socket = SocketAddr::new(addr, port);

    Ok(ClamClient { timeout, socket })
}

#[cfg(test)]
mod test {
    use crate::client::ClamClient;

    #[test]
    fn test_client_no_timeout() {
        let cclient = ClamClient::new("127.0.0.1", 3310).unwrap();
        let socket_addr =
            ::std::net::SocketAddr::new(::std::net::IpAddr::from([127, 0, 0, 1]), 3310);
        assert_eq!(cclient.socket, socket_addr);
        assert_eq!(cclient.timeout, None);
    }

    #[test]
    fn test_client_with_timeout() {
        let cclient = ClamClient::new_with_timeout("127.0.0.1", 3310, 60).unwrap();
        let socket_addr =
            ::std::net::SocketAddr::new(::std::net::IpAddr::from([127, 0, 0, 1]), 3310);
        assert_eq!(cclient.socket, socket_addr);
        assert_eq!(cclient.timeout, Some(::std::time::Duration::from_secs(60)));
    }
}
