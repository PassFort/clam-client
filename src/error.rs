#[derive(Debug, Fail)]
pub enum ClamError {
    #[fail(display = "{}", _0)]
    InvalidIpAddress(::std::net::AddrParseError),
    #[fail(display = "{}", _0)]
    ConnectionError(::std::io::Error),
    #[fail(display = "{}", _0)]
    CommandError(::std::io::Error),
    #[fail(display = "{}", _0)]
    InvalidData(::std::string::String),
    #[fail(display = "{}", _0)]
    IntParseError(::std::num::ParseIntError),
    #[fail(display = "{}", _0)]
    DateParseError(::chrono::format::ParseError),
    #[fail(display = "{}", _0)]
    StatsParseError(String)
}
