//! Human-written durations (`"10m"`, `"14d"`, `"90d"`).
//!
//! Configuration in `docs/08-BYO-INFRA.md §15` is written this way, and it should stay that way:
//! `absolute_ttl: 7776000` is unreviewable, while `absolute_ttl: "90d"` is obviously ninety days to
//! whoever approves the change. Parsing at load keeps that readability without any caller ever
//! seeing a string.

use core::fmt;
use core::str::FromStr;
use core::time::Duration;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A duration written the way an operator writes it.
///
/// Wraps [`core::time::Duration`] so it can carry `serde` and `Display` without orphan-rule games,
/// and derefs to it so callers use the standard type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HumanDuration(Duration);

impl HumanDuration {
    /// Build from a [`Duration`], for defaults declared in code.
    #[must_use]
    pub const fn new(duration: Duration) -> Self {
        Self(duration)
    }

    /// Build from whole seconds — the common case in `Default` impls.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    /// The wrapped standard duration.
    #[must_use]
    pub const fn as_duration(&self) -> Duration {
        self.0
    }

    /// Whole seconds, for the many APIs (JWT `exp`, cookie `Max-Age`, PostgreSQL timeouts) that
    /// want an integer.
    #[must_use]
    pub const fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    /// Whether the value is zero, which for a TTL means "expired on issue" and is nearly always a
    /// mistake worth checking for at the use site.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl From<Duration> for HumanDuration {
    fn from(value: Duration) -> Self {
        Self(value)
    }
}

impl From<HumanDuration> for Duration {
    fn from(value: HumanDuration) -> Self {
        value.0
    }
}

const UNITS: &[(&str, u64)] = &[
    ("ms", 1),
    ("s", 1_000),
    ("m", 60_000),
    ("h", 3_600_000),
    ("d", 86_400_000),
    ("w", 604_800_000),
];

impl FromStr for HumanDuration {
    type Err = DurationParseError;

    /// Accepts a sequence of `{integer}{unit}` terms, e.g. `"90d"`, `"1h30m"`, `"250ms"`.
    ///
    /// A bare number is rejected rather than assumed to be seconds: the assumption is invisible in
    /// review, and the difference between `30` meaning seconds and meaning minutes is the
    /// difference between a working and a broken session timeout.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let text = s.trim();
        if text.is_empty() {
            return Err(DurationParseError::Empty);
        }
        let mut total_ms: u64 = 0;
        let mut rest = text;
        let mut terms = 0_usize;

        while !rest.is_empty() {
            let digits_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            if digits_end == 0 {
                return Err(DurationParseError::Malformed);
            }
            let value: u64 =
                rest[..digits_end].parse().map_err(|_| DurationParseError::Overflow)?;
            rest = &rest[digits_end..];

            let (unit, millis) = UNITS
                .iter()
                // Longest-first so `ms` is not read as `m` followed by junk.
                .filter(|(unit, _)| rest.starts_with(unit))
                .max_by_key(|(unit, _)| unit.len())
                .ok_or(DurationParseError::UnknownUnit)?;
            rest = &rest[unit.len()..];

            total_ms = value
                .checked_mul(*millis)
                .and_then(|term| total_ms.checked_add(term))
                .ok_or(DurationParseError::Overflow)?;
            terms += 1;
        }

        if terms == 0 {
            return Err(DurationParseError::Malformed);
        }
        Ok(Self(Duration::from_millis(total_ms)))
    }
}

impl fmt::Display for HumanDuration {
    /// Renders in the largest unit that divides the value exactly, so a round-trip through
    /// configuration is stable and a diff of two config versions is readable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let millis = u64::try_from(self.0.as_millis()).unwrap_or(u64::MAX);
        if millis == 0 {
            return f.write_str("0s");
        }
        for (unit, unit_ms) in UNITS.iter().rev() {
            if millis % unit_ms == 0 {
                return write!(f, "{}{unit}", millis / unit_ms);
            }
        }
        write!(f, "{millis}ms")
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DurationVisitor;

        impl Visitor<'_> for DurationVisitor {
            type Value = HumanDuration;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration such as \"30s\", \"10m\", \"90d\"")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                value.parse().map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(DurationVisitor)
    }
}

/// Why a duration string was rejected. Short and specific — these appear in startup output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DurationParseError {
    /// The value was empty or whitespace.
    #[error("duration is empty")]
    Empty,
    /// The value is not a sequence of `{number}{unit}` terms.
    #[error("duration must be written as {{number}}{{unit}}, e.g. \"30s\", \"10m\", \"90d\"")]
    Malformed,
    /// A unit suffix was present but is not one of `ms`, `s`, `m`, `h`, `d`, `w`.
    #[error("duration unit must be one of ms, s, m, h, d, w")]
    UnknownUnit,
    /// The value does not fit in a `u64` of milliseconds.
    #[error("duration is too large")]
    Overflow,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_forms() {
        let cases = [
            ("30s", 30),
            ("10m", 600),
            ("15m", 900),
            ("24h", 86_400),
            ("14d", 1_209_600),
            ("90d", 7_776_000),
            ("1h30m", 5_400),
        ];
        for (text, secs) in cases {
            let parsed: HumanDuration = text.parse().expect(text);
            assert_eq!(parsed.as_secs(), secs, "input: {text}");
        }
        assert_eq!("250ms".parse::<HumanDuration>().unwrap().as_duration().as_millis(), 250);
    }

    #[test]
    fn display_round_trips_in_the_largest_exact_unit() {
        for text in ["30s", "10m", "90d", "250ms", "2w"] {
            let parsed: HumanDuration = text.parse().unwrap();
            assert_eq!(parsed.to_string(), text);
        }
        // Normalization is to the largest unit that divides exactly, so an equal value always
        // renders identically however it was written — which is what makes a config diff readable.
        assert_eq!("24h".parse::<HumanDuration>().unwrap().to_string(), "1d");
        assert_eq!("1h30m".parse::<HumanDuration>().unwrap().to_string(), "90m");
        assert_eq!("14d".parse::<HumanDuration>().unwrap().to_string(), "2w");
    }

    #[test]
    fn rejects_ambiguous_and_malformed_values() {
        assert_eq!("".parse::<HumanDuration>(), Err(DurationParseError::Empty));
        // A bare number is ambiguous, deliberately.
        assert_eq!("30".parse::<HumanDuration>(), Err(DurationParseError::UnknownUnit));
        assert_eq!("d".parse::<HumanDuration>(), Err(DurationParseError::Malformed));
        assert_eq!("10y".parse::<HumanDuration>(), Err(DurationParseError::UnknownUnit));
        assert_eq!(
            "99999999999999999999d".parse::<HumanDuration>(),
            Err(DurationParseError::Overflow)
        );
    }

    #[test]
    fn serde_round_trip() {
        let value: HumanDuration = "10m".parse().unwrap();
        let yaml = serde_yaml::to_string(&value).unwrap();
        assert_eq!(yaml.trim(), "10m");
        assert_eq!(serde_yaml::from_str::<HumanDuration>(&yaml).unwrap(), value);
    }
}
