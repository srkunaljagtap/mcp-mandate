//! Timestamps for log entries, without a date library.

use std::time::{SystemTime, UNIX_EPOCH};

/// `time` in UTC as RFC 3339 with milliseconds: `2026-10-17T19:30:01.123Z`.
pub(crate) fn rfc3339(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = since_epoch.as_secs();
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let of_day = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60,
        since_epoch.subsec_millis()
    )
}

/// The calendar date `days` after 1970-01-01 (Howard Hinnant's algorithm,
/// counting from 0000-03-01 so leap days fall at the end of each year).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let days = days + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn at(seconds: u64, millis: u64) -> String {
        rfc3339(UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_millis(millis))
    }

    #[test]
    fn formats_utc_with_milliseconds() {
        assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(946_684_799, 999), "1999-12-31T23:59:59.999Z");
        assert_eq!(at(946_684_800, 0), "2000-01-01T00:00:00.000Z");
    }

    #[test]
    fn handles_leap_days() {
        assert_eq!(at(951_782_400, 0), "2000-02-29T00:00:00.000Z");
        assert_eq!(at(951_868_800, 0), "2000-03-01T00:00:00.000Z");
        assert_eq!(at(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
        assert_eq!(at(4_107_542_400, 0), "2100-03-01T00:00:00.000Z");
    }
}
