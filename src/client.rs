use error::ClamError;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::TcpStream;
use std::time::Duration;
use std::io::{Write, Read, BufReader};
use response::{ClamVersion, ClamStats};

pub type ClamResult<T> = ::std::result::Result<T, ClamError>;

pub struct ClamClient {
    socket: SocketAddr,
    timeout: Option<Duration>
}

impl ClamClient {
    pub fn new(ip: &str, port: u16) -> ClamResult<ClamClient> {
        build(ip, port, None)
    }

    pub fn new_with_timeout(ip: &str, port: u16, timeout_secs: u64) -> ClamResult<ClamClient> {
        build(ip, port, Some(Duration::from_secs(timeout_secs)))
    }

    pub fn ping(&self) -> ClamResult<bool> {
        match self.send_command(b"PING\0") {
            Ok(resp) => Ok(resp == "PONG"),
            Err(e) => Err(e)
        }
    }

    pub fn version(&self) -> ClamResult<ClamVersion> {
        let resp = self.send_command(b"VERSION\0")?;
        ClamVersion::parse(resp)
    }

    pub fn reload(&self) -> ClamResult<String> {
        self.send_command(b"RELOAD\0")
    }

    pub fn scan_path(&self, path: &str, continue_on_virus: bool) -> ClamResult<String> {
        if continue_on_virus {
            self.send_command(&format!("CONTSCAN {}\0", path).into_bytes())
        } else {
            self.send_command(&format!("SCAN {}\0", path).into_bytes())
        }
    }

    // TODO: Error handling, actual results, etc.
    pub fn scan_stream<T: Read>(&self, stream: T) -> ClamResult<bool> {
        let mut reader = BufReader::new(stream);
        let mut buffer = [0; 4096];
        let mut connection = self.connect()?; 

        &connection.write(b"zINSTREAM\0");
        loop {
            let bytes_read = reader.read(&mut buffer).unwrap();
            &connection.write(&bytes_read.to_be().to_bytes()).unwrap();
            &connection.write(&buffer).unwrap();
            if bytes_read == 0 {
                &connection.shutdown(::std::net::Shutdown::Write);
                break;
            }
        }

        let mut result = String::new();
        connection.read_to_string(&mut result).unwrap();
        println!("{}", result);

        Ok(true)
    }

    pub fn stats(&self) -> ClamResult<ClamStats> {
        let resp: String = self.send_command(b"zSTATS\0")?;
        ClamStats::parse(resp)
    }

    pub fn shutdown(&self) -> ClamResult<String> {
        self.send_command(b"SHUTDOWN\0")
    }

    fn send_command(&self, command: &[u8]) -> ClamResult<String> {
        let mut connection = self.connect()?;

        return match connection.write_all(command) {
            Ok(_) => {
                let mut result = String::new();
                return match connection.read_to_string(&mut result) {
                    Ok(len) => {
                        if len > 1 {
                            result.truncate(len - 1);
                        }

                        Ok(result)
                    },
                    Err(e) => Err(ClamError::CommandError(e))
                }
            },
            Err(e) => {
                Err(ClamError::CommandError(e))
            }
        }
    }

    fn connect(&self) -> ClamResult<TcpStream> {
        let connection = if let Some(t) = self.timeout {
            TcpStream::connect_timeout(&self.socket, t)
        } else {
            TcpStream::connect(&self.socket)
        };

        match connection {
            Ok(handle) => Ok(handle),
            Err(e) => Err(ClamError::ConnectionError(e))
        }
    }
}

fn build(ip: &str, port: u16, timeout: Option<Duration>) -> ClamResult<ClamClient> {
    let addr: IpAddr = match ip.parse() {
        Ok(v) => v,
        Err(e) => return Err(ClamError::InvalidIpAddress(e))
    };

    let socket = SocketAddr::new(addr, port);

    Ok(ClamClient {
        socket: socket,
        timeout: timeout
    })
}