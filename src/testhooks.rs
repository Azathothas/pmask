//! Test-only environment switches, compiled out of a release build.
//!
//! The gate builds with `--features testbins,test-hooks`, so the fault
//! injection and probe overrides are available to the shell suites.  A
//! release build has neither feature and the functions below return the
//! neutral value without reading the environment.  A caller that sets
//! `PMASK_FAULT_*` or `PMASK_PROBE_*` cannot degrade a deployed binary.
//!
//! `PMASK_NO_SELFMASK` is not here: it is a documented debugging escape,
//! not a test hook.

/// True when `name` is set and the test-hooks feature is on.
#[cfg(feature = "test-hooks")]
pub fn flag(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

/// False in a release build.
#[cfg(not(feature = "test-hooks"))]
pub fn flag(_name: &str) -> bool {
    false
}

/// Parse `name` as `T`, or `None`.
#[cfg(feature = "test-hooks")]
pub fn number<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// `None` in a release build.
#[cfg(not(feature = "test-hooks"))]
pub fn number<T: std::str::FromStr>(_name: &str) -> Option<T> {
    None
}

/// Strict `0`/`1` parse for a fault switch.  Any other value is not a
/// boolean the hook was meant to receive, so it does not switch the
/// fault on (and does not report `Some(false)` either).
#[cfg(feature = "test-hooks")]
fn parse_switch(v: &str) -> Option<bool> {
    match v {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// `Some(true)` only for `1`, `Some(false)` only for `0`.
#[cfg(feature = "test-hooks")]
pub fn bool_opt(name: &str) -> Option<bool> {
    parse_switch(&std::env::var(name).ok()?)
}

/// `None` in a release build.
#[cfg(not(feature = "test-hooks"))]
pub fn bool_opt(_name: &str) -> Option<bool> {
    None
}

#[cfg(all(test, feature = "test-hooks"))]
mod tests {
    use super::parse_switch;

    #[test]
    fn only_zero_and_one_are_switches() {
        assert_eq!(parse_switch("1"), Some(true));
        assert_eq!(parse_switch("0"), Some(false));
        // A typo used to read as `Some(false)`; it is not a switch.
        assert_eq!(parse_switch("true"), None);
        assert_eq!(parse_switch("yes"), None);
        assert_eq!(parse_switch(""), None);
        assert_eq!(parse_switch("2"), None);
    }
}
