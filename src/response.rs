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
}

#[derive(Debug)]
pub struct ClamVersion {
    pub version_tag: String,
    pub build_number: u64,
    pub release_date: DateTime<Utc>,
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

//TODO
impl ClamStats {
    pub fn parse(s_string: &str) -> ClamResult<Self> {
        // let lines: HashMap<String, String> = s_string.lines()
        //     .filter(|s| s != &"" && s.contains(":"))
        //     .flat_map(|l| l.split(":"))
        //     .map(|l| l.trim().to_owned())
        //     .tuples()
        //     .collect();

        // println!("{:?}", lines);

        // Ok(ClamStats {
        //     pools: lines["POOLS"].parse().unwrap()
        // })
        // println!("{:?}", parse_stats(&s_string).unwrap_err());
        Ok(parse_stats(s_string).unwrap().1)
    }

    //POOLS: 1\n\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 12 idle-timeout 30\nQUEUE: 0 items\n\tSTATS 0.000213 \n\nMEMSTATS: heap 8.484M mmap 0.320M used 6.585M free 1.900M releasable 0.057M pools 1 pools_used 565.435M pools_total 565.456M\nEND
}

named!(parse_stats<&str, ClamStats>,
    do_parse!(
        tag!("POOLS: ") >>
        pools: map_res!(take_until_and_consume!("\n\n"), u64::from_str) >>
        tag!("STATE: ") >>
        state: map_res!(take_until_and_consume!("\n"), FromStr::from_str) >>
        tag!("THREADS: ") >>
        take_until_and_consume!("live ") >>
        threads_live: map_res!(take_until_and_consume!("  "), u64::from_str) >>
        take_until_and_consume!("idle ") >>
        threads_idle: map_res!(take_until_and_consume!(" "), u64::from_str) >>
        take_until_and_consume!("max ") >>
        threads_max: map_res!(take_until_and_consume!(" "), u64::from_str) >> 
        take_until_and_consume!("idle-timeout ") >>
        threads_idle_timeout_secs: map_res!(take_until_and_consume!("\n"), u64::from_str) >> 
        tag!("QUEUE: ") >>
        queue: map_res!(take_until_and_consume!(" items\n"), u64::from_str) >> 
        take_until_and_consume!("\n\n") >>
        (
            ClamStats {
                pools,
                state,
                threads_live,
                threads_idle,
                threads_max,
                threads_idle_timeout_secs,
                queue
            }
        )
    )
);
