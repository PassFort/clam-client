use chrono::{DateTime, TimeZone, Utc};
use client::ClamResult;
use error::ClamError;
use std::str::FromStr;

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

#[derive(Debug)]
pub struct ClamVersion {
    pub version_tag: String,
    pub build_number: u64,
    pub release_date: DateTime<Utc>,
}

#[derive(Debug)]
pub enum ClamScanResult {
    Ok,
    Found(String),
    Error(String),
}

impl ClamScanResult {
    pub fn parse(s_string: String) -> ClamResult<ClamScanResult> {
        if s_string.ends_with("OK") || s_string.ends_with("OK\0") {
            return Ok(ClamScanResult::Ok)
        }

        if s_string.contains("FOUND") {
            let virus = s_string.split_whitespace()
                .skip(1)
                .take_while(|s| !s.starts_with("FOUND"))
                .collect::<String>();
                
            return Ok(ClamScanResult::Found(virus))
        }

        Ok(ClamScanResult::Error(s_string))
    }
}

impl ClamVersion {
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
    pub fn parse(s_string: &str) -> ClamResult<Self> {
        match parse_stats(s_string) {
            Ok(v) => Ok(v.1),
            Err(_) => Err(ClamError::StatsParseError(s_string.to_owned()))
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
