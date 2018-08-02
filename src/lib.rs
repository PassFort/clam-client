#[macro_use]
extern crate failure;
#[macro_use]
extern crate nom;

extern crate byteorder;
extern crate chrono;

pub mod client;
pub mod error;
pub mod response;

#[cfg(test)]
mod tests {
    use chrono::prelude::*;
    use response;

    #[test]
    fn parse_version() {
        let raw = "ClamAV 0.100.0/24802/Wed Aug  1 08:43:37 2018".to_owned();
        let parsed = response::ClamVersion {
            version_tag: "ClamAV 0.100.0".to_owned(),
            build_number: 24802,
            release_date: Utc
                .datetime_from_str("Wed Aug  1 08:43:37 2018", "%a %b %e %T %Y")
                .unwrap(),
        };
        let result = response::ClamVersion::parse(raw).unwrap();

        assert_eq!(result.version_tag, parsed.version_tag);
        assert_eq!(result.build_number, parsed.build_number);
        assert_eq!(result.release_date, parsed.release_date);
    }
}
