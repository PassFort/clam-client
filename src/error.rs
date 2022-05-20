//! Simple error interface for clam_client. This simply wraps other common error types, the reason
//! for this is two-fold:
//!
//! * Enable propogation of errors all the way up the chain.
//! * Provide one simple error handling mechanism to the caller.
//!
//! Whilst this may not be the most optimal approach, and is subject to change, it does make
//! client side handling and result propogation very simple.

/// `ClamError` is the primary interface for all errors emitted by `clam_client`.
#[derive(Debug, Fail)]
pub enum ClamError {
    /// Generated when an invalid IP address is supplied to `ClamClient::new(..)`
    #[fail(display = "{}", _0)]
    InvalidIpAddress(::std::net::AddrParseError),
    /// Generated when a`ClamClient` is unable to connect to the specified ClamAV socket
    #[fail(display = "{}", _0)]
    ConnectionError(::std::io::Error),
    /// Generated when the command issued cannot be sucesffully written to the ClamAV socket
    #[fail(display = "{}", _0)]
    CommandError(::std::io::Error),
    /// Generated when the ClamAV response cannot be parsed by `clam_client::response::T`
    #[fail(display = "Could not parse: {}", _0)]
    InvalidData(::std::string::String),
    /// Generated when an integer cannot be parsed, wrapped in `ClamError` for ease
    #[fail(display = "{}", _0)]
    IntParseError(::std::num::ParseIntError),
    /// Generated when a date cannot be parsed by `chrono`, wrapped in `ClamError` for ease
    #[fail(display = "{}", _0)]
    DateParseError(::chrono::format::ParseError),
    /// Genarated when the data length written to the ClamD socket exceeds 2^32
    #[fail(display = "Invalid data length sent: {}", _0)]
    InvalidDataLengthError(usize),
}
