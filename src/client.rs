use byteorder::{BigEndian, ByteOrder};
use error::ClamError;
use response::{ClamStats, ClamVersion};
use std::io::{BufReader, Read, Write};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

pub type ClamResult<T> = ::std::result::Result<T, ClamError>;

pub struct ClamClient {
    socket: SocketAddr,
    timeout: Option<Duration>,
}

impl ClamClient {
    pub fn new(ip: &str, port: u16) -> ClamResult<ClamClient> {
        build(ip, port, None)
    }

    pub fn new_with_timeout(ip: &str, port: u16, timeout_secs: u64) -> ClamResult<ClamClient> {
        build(ip, port, Some(Duration::from_secs(timeout_secs)))
    }

    pub fn ping(&self) -> ClamResult<bool> {
        match self.send_command(b"zPING\0") {
            Ok(resp) => Ok(resp == "PONG"),
            Err(e) => Err(e),
        }
    }

    pub fn version(&self) -> ClamResult<ClamVersion> {
        let resp = self.send_command(b"zVERSION\0")?;
        ClamVersion::parse(resp)
    }

    pub fn reload(&self) -> ClamResult<String> {
        self.send_command(b"zRELOAD\0")
    }

    pub fn scan_path(&self, path: &str, continue_on_virus: bool) -> ClamResult<String> {
        if continue_on_virus {
            self.send_command(&format!("zCONTSCAN {}\0", path).into_bytes())
        } else {
            self.send_command(&format!("zSCAN {}\0", path).into_bytes())
        }
    }

    // TODO: Error handling, actual results, etc.
    pub fn scan_stream<T: Read>(&self, stream: T) -> ClamResult<String> {
        let mut reader = BufReader::new(stream);
        let mut buffer = [0; 4096];
        let mut length_buffer = [0; 4];
        let mut connection = self.connect()?;

        self.connection_write(&connection, b"zINSTREAM\0")?;

        while let Ok(bytes_read) = reader.read(&mut buffer) {
            BigEndian::write_u32(&mut length_buffer, bytes_read as u32);

            self.connection_write(&connection, &length_buffer)?;
            self.connection_write(&connection, &buffer)?;

            if bytes_read < 4096 {
                break;
            }
        }

        self.connection_write(&connection, &[0, 0, 0, 0])?;
        connection.shutdown(::std::net::Shutdown::Write).unwrap();

        let mut result = String::new();
        connection.read_to_string(&mut result).unwrap();

        Ok(result)
    }

    pub fn stats(&self) -> ClamResult<ClamStats> {
        let resp: String = self.send_command(b"zSTATS\0")?;
        ClamStats::parse(&resp)
    }

    pub fn shutdown(&self) -> ClamResult<String> {
        self.send_command(b"zSHUTDOWN\0")
    }

    fn send_command(&self, command: &[u8]) -> ClamResult<String> {
        let mut connection = self.connect()?;

        match connection.write_all(command) {
            Ok(_) => {
                let mut result = String::new();
                match connection.read_to_string(&mut result) {
                    Ok(len) => {
                        if len > 1 {
                            result.truncate(len - 1);
                        }

                        Ok(result)
                    }
                    Err(e) => Err(ClamError::CommandError(e)),
                }
            }
            Err(e) => Err(ClamError::CommandError(e)),
        }
    }

    fn connection_write(&self, mut connection: &TcpStream, command: &[u8]) -> ClamResult<usize> {
        match connection.write(command) {
            Ok(v) => Ok(v),
            Err(e) => Err(ClamError::CommandError(e)),
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
            Err(e) => Err(ClamError::ConnectionError(e)),
        }
    }
}

fn build(ip: &str, port: u16, timeout: Option<Duration>) -> ClamResult<ClamClient> {
    let addr: IpAddr = match ip.parse() {
        Ok(v) => v,
        Err(e) => return Err(ClamError::InvalidIpAddress(e)),
    };

    let socket = SocketAddr::new(addr, port);

    Ok(ClamClient { timeout, socket })
}
