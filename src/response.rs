//! The `response` module is responsible for parsing the responses issued to use
//! by ClamAV. To do so, it relies on two external crates, namely, `nom` and `chrono`.
//!
//! All structs and enums derive `Debug` for ease of client send debugging and development.

use crate::client::ClamResult;
use crate::error::ClamError;
use chrono::{DateTime, TimeZone, Utc};
use std::str::FromStr;

/// `ClamStats` provides all of the metrics that Clam provides via the `STATS` command
/// as at version 0.100.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, PartialOrd)]
pub struct ClamStats {
    /// The number of `pools` available to ClamAV
    pub pools: u64,
    /// The state of the responding Clam Daemon
    pub state: String,
    /// The number of active threads owned by the Clam Daemon
    pub threads_live: u64,
    /// The number of idle threads owned by the Clam Daemon
    pub threads_idle: u64,
    /// The maximum number of threads the Clam Daemon can spawn
    pub threads_max: u64,
    /// The timeout (seconds) before a thread is determined to be idle
    pub threads_idle_timeout_secs: u64,
    /// The number of items in the queue awaiting processing
    pub queue: u64,
    /// Total memory allocated to the heap
    pub mem_heap: String,
    /// Amount of mmap'd memory used
    pub mem_mmap: String,
    /// Total memory used by the daemon
    pub mem_used: String,
    /// Total memory available to the daemon not in use
    pub mem_free: String,
    /// Total memory re
    pub mem_releasable: String,
    /// Total number of pools in use by the daemon
    pub pools_used: String,
    /// Total number of pools available to the daemon
    pub pools_total: String,
}

/// `ClamVersion` provides all of the Clam meta-information provided by the `VERSION` command
#[derive(Debug, PartialEq, PartialOrd)]
pub struct ClamVersion {
    /// The name and version number of the responding daemon
    pub version_tag: String,
    /// The build number of the responding daemon
    pub build_number: u64,
    /// The release date for the responding daemon
    pub release_date: DateTime<Utc>,
}

/// `ClamScanResult` Provides a `match` 'friendly' interface for receiving the result of a scan.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, PartialOrd)]
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
    /// multiple errors.
    ///
    /// *Note*: If performing a stream scan, the result will be converted to a single `ClamScanResult` by
    /// the caller.
    pub fn parse<T: AsRef<str>>(s_string: T) -> Vec<ClamScanResult> {
        s_string
            .as_ref()
            .split('\0')
            .filter(|s| s != &"")
            .map(|s| {
                if s.ends_with("OK") {
                    return ClamScanResult::Ok;
                }

                if s.contains("FOUND") {
                    let mut split = s.split_whitespace();
                    let path: String = split.next().unwrap().trim_end_matches(':').to_owned();
                    let virus = split
                        .take_while(|s| !s.starts_with("FOUND"))
                        .collect::<String>();

                    return ClamScanResult::Found(path, virus);
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
        let parts: Vec<String> = v_string
            .trim_end_matches('\0')
            .split('/')
            .map(|s| s.to_owned())
            .collect();

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
    /// raw form inside `ClamError::InvalidData`.
    pub fn parse(s_string: &str) -> ClamResult<Self> {
        match parse_stats(s_string) {
            Ok(v) => Ok(v.1),
            Err(_) => Err(ClamError::InvalidData(s_string.to_owned())),
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

#[cfg(test)]
mod tests {
    use crate::response;
    use chrono::prelude::*;

    static VERSION_STRING: &'static str = "ClamAV 0.100.0/24802/Wed Aug  1 08:43:37 2018\0";
    static STATS_STRING: &'static str = "POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 12 idle-timeout 30\nQUEUE: 0 items\n\tSTATS 0.000394\n\nMEMSTATS: heap 9.082M mmap 0.000M used 6.902M free 2.184M releasable 0.129M pools 1 pools_used 565.979M pools_total 565.999M\nEND\0";

    #[test]
    fn test_version_parse_version_tag() {
        let raw = VERSION_STRING.to_owned();
        let parsed = response::ClamVersion::parse(raw).unwrap();
        assert_eq!(parsed.version_tag, "ClamAV 0.100.0".to_string());
    }

    #[test]
    fn test_version_parse_build_number() {
        let raw = VERSION_STRING.to_owned();
        let parsed = response::ClamVersion::parse(raw).unwrap();
        assert_eq!(parsed.build_number, 24802);
    }

    #[test]
    fn test_version_parse_publish_dt() {
        let raw = VERSION_STRING.to_owned();
        let parsed = response::ClamVersion::parse(raw).unwrap();
        assert_eq!(
            parsed.release_date,
            Utc.datetime_from_str("Wed Aug  1 08:43:37 2018", "%a %b %e %T %Y")
                .unwrap()
        );
    }

    #[test]
    fn test_result_parse_ok() {
        let raw = "/some/file: OK\0";
        let parsed = response::ClamScanResult::parse(raw);
        assert_eq!(parsed[0], response::ClamScanResult::Ok);
    }

    #[test]
    fn test_result_parse_found() {
        let raw = "/some/file: SOME_BAD-Virus FOUND\0";
        let parsed = response::ClamScanResult::parse(raw);
        assert_eq!(
            parsed[0],
            response::ClamScanResult::Found("/some/file".to_string(), "SOME_BAD-Virus".to_string())
        );
    }

    #[test]
    fn test_result_parse_multi_found() {
        let raw = "/some/file: SOME_BAD-Virus FOUND\0/some/other_file: SOME_V*BAD-Virus FOUND\0";
        let parsed = response::ClamScanResult::parse(raw);
        assert_eq!(
            parsed[0],
            response::ClamScanResult::Found("/some/file".to_string(), "SOME_BAD-Virus".to_string())
        );
        assert_eq!(
            parsed[1],
            response::ClamScanResult::Found(
                "/some/other_file".to_string(),
                "SOME_V*BAD-Virus".to_string()
            )
        );
    }

    #[test]
    fn test_result_parse_error() {
        let raw = "/some/file: lstat() failed or some other random error\0";
        let parsed = response::ClamScanResult::parse(raw);
        assert_eq!(
            parsed[0],
            response::ClamScanResult::Error(
                "/some/file: lstat() failed or some other random error".to_string()
            )
        );
    }

    #[test]
    fn test_stats_parse_pools() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.pools, 1);
    }

    #[test]
    fn test_stats_parse_state() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.state, "VALID PRIMARY".to_string());
    }

    #[test]
    fn test_stats_parse_live_threads() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.threads_live, 1);
    }

    #[test]
    fn test_stats_parse_idle_threads() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.threads_idle, 0);
    }

    #[test]
    fn test_stats_parse_max_threads() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.threads_max, 12);
    }

    #[test]
    fn test_stats_parse_threads_timeout() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.threads_idle_timeout_secs, 30);
    }

    #[test]
    fn test_stats_parse_queue() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.queue, 0);
    }

    #[test]
    fn test_stats_parse_mem_heap() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_heap, "9.082M".to_string());
    }

    #[test]
    fn test_stats_parse_mem_mmap() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_mmap, "0.000M".to_string());
    }

    #[test]
    fn test_stats_parse_mem_used() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_used, "6.902M".to_string());
    }

    #[test]
    fn test_stats_parse_mem_free() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_free, "2.184M".to_string());
    }

    #[test]
    fn test_stats_parse_mem_releaseable() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.mem_releasable, "0.129M".to_string());
    }

    #[test]
    fn test_stats_parse_pools_used() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.pools_used, "565.979M".to_string());
    }

    #[test]
    fn test_stats_parse_pools_total() {
        let parsed = response::ClamStats::parse(STATS_STRING).unwrap();
        assert_eq!(parsed.pools_total, "565.999M".to_string());
    }
}
