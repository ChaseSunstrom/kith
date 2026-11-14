//! A CronJob's schedule: the five fields of cron (minute, hour, day of the month, month,
//! day of the week) or one of its names (`@hourly`), read in UTC.

/// The minutes a schedule names.
#[derive(Debug, Clone, PartialEq)]
pub struct Schedule {
    /// A bit for each value of each field, in the fields' order.
    fields: [u64; 5],
    /// Both the day of the month and the day of the week are said: a day that is either
    /// is one (cron's rule).
    either: bool,
}

/// Each field: what it is, its least and its greatest, and the names its values have.
const FIELDS: [(&str, u32, u32, &[&str]); 5] = [
    ("minute", 0, 59, &[]),
    ("hour", 0, 23, &[]),
    ("day of the month", 1, 31, &[]),
    (
        "month",
        1,
        12,
        &[
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
        ],
    ),
    (
        "day of the week",
        0,
        7,
        &["sun", "mon", "tue", "wed", "thu", "fri", "sat"],
    ),
];

const NAMED: [(&str, &str); 7] = [
    ("@yearly", "0 0 1 1 *"),
    ("@annually", "0 0 1 1 *"),
    ("@monthly", "0 0 1 * *"),
    ("@weekly", "0 0 * * 0"),
    ("@daily", "0 0 * * *"),
    ("@midnight", "0 0 * * *"),
    ("@hourly", "0 * * * *"),
];

impl Schedule {
    pub fn parse(text: &str) -> Result<Schedule, String> {
        let named = NAMED.iter().find(|(name, _)| *name == text.trim());
        let parts: Vec<&str> = named.map_or(text, |(_, is)| is).split_whitespace().collect();
        if parts.len() != 5 {
            return Err(format!(
                "`{text}` is not five fields (minute, hour, day of the month, month, day of the week)"
            ));
        }
        let mut fields = [0; 5];
        for ((part, (what, min, max, names)), bits) in parts.iter().zip(FIELDS).zip(&mut fields) {
            *bits = field(part, min, max, names).ok_or(format!("`{part}` is not a {what} ({min} to {max})"))?;
        }
        // (Sunday is 0, and 7.)
        fields[4] = (fields[4] | fields[4] >> 7) & 0x7f;
        let said = |n: usize| !parts[n].starts_with(['*', '?']);
        Ok(Schedule {
            fields,
            either: said(2) && said(4),
        })
    }

    /// Whether the minute `secs` (since the epoch) is in is one of them.
    pub fn due(&self, secs: u64) -> bool {
        // (`2026-11-12T09:30:00Z`: the parts are where they are.)
        let at = crate::store::rfc3339(secs);
        let part = |from: usize| at.get(from..from + 2).and_then(|part| part.parse::<u32>().ok());
        let has = |n: usize, value: Option<u32>| value.is_some_and(|value| self.fields[n] >> value & 1 == 1);
        // (The first day there was, was a Thursday.)
        let (day, weekday) = (has(2, part(8)), has(4, Some(((secs / 86400 + 4) % 7) as u32)));
        let days = if self.either { day || weekday } else { day && weekday };
        has(0, part(14)) && has(1, part(11)) && has(3, part(5)) && days
    }
}

/// The values one field names, a bit each: `*`, `5`, `1-5`, `*/15`, `10-40/10`, `5/15`
/// (from 5 on), or several with commas between.
fn field(text: &str, min: u32, max: u32, names: &[&str]) -> Option<u64> {
    let number = |text: &str| {
        let named = names.iter().position(|name| text.eq_ignore_ascii_case(name));
        let number = named.map(|n| n as u32 + min).or_else(|| text.parse().ok());
        number.filter(|n| (min..=max).contains(n))
    };
    let mut bits = 0;
    for part in text.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => (range, step.parse::<usize>().ok().filter(|step| *step > 0)?),
            None => (part, 1),
        };
        let (from, to) = match range.split_once('-') {
            _ if range == "*" || range == "?" => (min, max),
            Some((from, to)) => (number(from)?, number(to)?),
            None if part.contains('/') => (number(range)?, max),
            None => (number(range)?, number(range)?),
        };
        if from > to {
            return None;
        }
        for n in (from..=to).step_by(step) {
            bits |= 1 << n;
        }
    }
    Some(bits)
}

#[cfg(test)]
mod tests {
    use super::Schedule;

    #[test]
    fn a_schedule_names_its_minutes_and_a_wrong_one_is_said() {
        // Friday 2026-11-13 09:30, a minute later, and the Saturday after.
        let (friday, saturday) = (1_794_562_200, 1_794_648_600);
        let due = |schedule: &str, at: u64| Schedule::parse(schedule).unwrap().due(at);
        for always in [
            "* * * * *",
            "*/15 9-17 * * mon-fri",
            "30 9 13 NOV ?",
            "0,30 */3 * 11 5",
            "20/10 * * * *",
        ] {
            assert!(due(always, friday), "{always}");
            assert!(due(always, friday + 59), "{always}: the whole minute");
        }
        assert!(!due("*/15 9-17 * * mon-fri", friday + 60));
        assert!(!due("*/15 9-17 * * mon-fri", saturday));
        assert!(due("@hourly", friday + 1800) && !due("@hourly", friday));
        assert!(due("@daily", 1_794_528_000) && due("@yearly", 1_798_761_600));
        // Sunday is 0 and 7 (2026-11-15 12:00).
        assert!(due("0 12 * * 0", 1_794_744_000) && due("0 12 * * 7", 1_794_744_000));
        // Both days said: a day that is either. One said: that one.
        let (friday_13, friday_20, sunday_13, monday_14) = (1_794_528_000, 1_795_132_800, 1_797_120_000, 1_797_206_400);
        for (at, either, of_month) in [
            (friday_13, true, true),
            (friday_20, true, false),
            (sunday_13, true, true),
            (monday_14, false, false),
        ] {
            assert_eq!(due("0 0 13 * 5", at), either);
            assert_eq!(due("0 0 13 * *", at), of_month);
        }
        for wrong in [
            "",
            "* * * *",
            "60 * * * *",
            "*/0 * * * *",
            "5-1 * * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 8",
            "a * * * *",
            "@often",
        ] {
            assert!(Schedule::parse(wrong).is_err(), "{wrong}");
        }
        assert!(
            Schedule::parse("61 * * * *")
                .unwrap_err()
                .contains("`61` is not a minute (0 to 59)")
        );
    }
}
