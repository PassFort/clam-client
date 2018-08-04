//! The `response` module is responsibe for parsing the responses issued to use
//! by ClamAV. To do so, it relies on two external crates, namely, `nom` and `chrono`.
//! 
//! All structs and enums derive `Debug` for ease of client send debugging and development.

use chrono::{DateTime, TimeZone, Utc};
use client::ClamResult;
use error::ClamError;
use std::str::FromStr;

/// `ClamStats` provides all of the metrics that Clam provides via the `STATS` command
/// as at version 0.100. 
#[derive(Debug)]
pub struct ClamStats {
    pub pools: u64,
    pub state: String,
    pub threads_live: u64,
    pub threads_idle: u64,
    pub threads_max: u64,
    pub threads_idle_timeout_secs: u64,
    pub queue: u64,
    pub mem_heap: String,
    pub mem_mmap: String,
    pub mem_used: String,
    pub mem_free: String,
    pub mem_releasable: String,
    pub pools_used: String,
    pub pools_total: String,
}

/// `ClamVersion` provdes all of the Clam meta-information provided by the `VERSION` command
#[derive(Debug)]
pub struct ClamVersion {
    pub version_tag: String,
    pub build_number: u64,
    pub release_date: DateTime<Utc>,
}

/// `ClamScanResult` Provides a `match` 'friendly' interface for receiving the result of a scan.
#[derive(Debug, Clone)]
pub enum ClamScanResult {
    /// An `Ok` response means that Clam found no virus in the given file/directory.
    Ok,
    /// A `Found` response means that Clam did find one or more virus('s) in the given file/directory, 
    /// the first value of `Found` is the location where the virus was found, and the second value is
    /// the name of the virus detected. 
    /// 
    /// *Note*: When performing a stream scan, the location is redundant, and will always be `instream`.
    Found(String, String),
    /// An `Error` response means that Clam encountered an error whilst processing the request,
    /// for example, if the given file/directory couldn't be found.
    Error(String),
}

impl ClamScanResult {
    /// `ClamScanResult::parse` takes a Clam scan result string and parses into into a `Vec<ClamScanResult`.
    /// A vec must be used because Clam may scan multiple files in one request, or may encounter
    /// multuple errors. 
    /// 
    /// *Note*: If performing a stream scan, the result will be converted to a single `ClamScanResult` by
    /// the caller.
    pub fn parse<T: AsRef<str>>(s_string: T) -> Vec<ClamScanResult> {
        s_string.as_ref().split('\0')
            .filter(|s| s != &"")
            .map(|s| {
                if s.ends_with("OK") {
                    return ClamScanResult::Ok
                }

                if s.contains("FOUND") {
                    let mut split = s.split_whitespace();
                    let path: String = split.next().unwrap().trim_right_matches(':').to_owned();
                    let virus = split
                        .take_while(|s| !s.starts_with("FOUND"))
                        .collect::<String>();
                        
                    return ClamScanResult::Found(path, virus)
                }

                ClamScanResult::Error(s.to_owned())
            })
            .collect::<Vec<ClamScanResult>>()
    }
}

impl ClamVersion {
    /// `ClamVersion::parse` takes a string returned from the Clam `VERSION` command and parses it
    /// into a strongly typed struct assuming it retains a standard format of
    /// `version tag/build no/publish datetime`
    pub fn parse(v_string: String) -> ClamResult<Self> {
        let parts: Vec<String> = v_string.split('/').map(|s| s.to_owned()).collect();

        if parts.len() != 3 {
            return Err(ClamError::InvalidData(v_string));
        }

        let bn = match parts[1].parse() {
            Ok(v) => v,
            Err(e) => return Err(ClamError::IntParseError(e)),
        };

        let dt = match Utc.datetime_from_str(&parts[2], "%a %b %e %T %Y") {
            Ok(v) => v,
            Err(e) => return Err(ClamError::DateParseError(e)),
        };

        Ok(ClamVersion {
            version_tag: parts[0].to_owned(),
            build_number: bn,
            release_date: dt,
        })
    }
}

impl ClamStats {
    /// `ClamStats::parse` takes a statistics output of the Clam `STATS` command and uses
    /// nom to parse that into a strongly typed struct. 
    /// 
    /// Given that this is likely to be the most volatile area of returned data, it is likely 
    /// that this will fail across different versions. This parses the data expected as of 
    /// version 0.100.0. If it cannot parse the data, then the result is returned in its
    /// raw form insude `ClamError::InvalidData`.
    pub fn parse(s_string: &str) -> ClamResult<Self> {
        match parse_stats(s_string) {
            Ok(v) => Ok(v.1),
            Err(_) => Err(ClamError::InvalidData(s_string.to_owned()))
        }
    }
}

named!(parse_stats<&str, ClamStats>,
    do_parse!(
        tag!("POOLS: ") >>
        pools: map_res!(take_until_and_consume!("\n\nSTATE: "), u64::from_str) >>
        state: map_res!(take_until_and_consume!("\nTHREADS: live "), FromStr::from_str) >>
        threads_live: map_res!(take_until_and_consume!("  idle "), u64::from_str) >>
        threads_idle: map_res!(take_until_and_consume!(" max "), u64::from_str) >>
        threads_max: map_res!(take_until_and_consume!(" idle-timeout "), u64::from_str) >> 
        threads_idle_timeout_secs: map_res!(take_until_and_consume!("\nQUEUE: "), u64::from_str) >>
        queue: map_res!(take_until_and_consume!(" items\n"), u64::from_str) >> 
        take_until_and_consume!("heap ") >>
        mem_heap: map_res!(take_until_and_consume!(" mmap "), FromStr::from_str) >>
        mem_mmap: map_res!(take_until_and_consume!(" used "), FromStr::from_str) >>
        mem_used: map_res!(take_until_and_consume!(" free "), FromStr::from_str) >>
        mem_free: map_res!(take_until_and_consume!(" releasable "), FromStr::from_str) >>
        mem_releasable: map_res!(take_until_and_consume!(" pools "), FromStr::from_str) >>
        take_until_and_consume!("pools_used ") >>
        pools_used: map_res!(take_until_and_consume!(" pools_total "), FromStr::from_str) >>
        pools_total: map_res!(take_until!("\n"), FromStr::from_str) >>
        (
            ClamStats {
                pools,
                state,
                threads_live,
                threads_idle,
                threads_max,
                threads_idle_timeout_secs,
                queue,
                mem_heap,
                mem_mmap,
                mem_used,
                mem_free,
                mem_releasable,
                pools_used,
                pools_total
            }
        )
    )
);
