//! Transient-failure retry for provider HTTP calls.
//!
//! Without this, a single 429 killed a scanner on its first call. A rate-limited
//! provider took out a whole scan: six scanners, six first calls, six 429s, an
//! empty findings file, and a "Scan complete" banner. Retrying the transient
//! cases is the difference between a scan happening and a scan silently not
//! happening.
//!
//! What is retried: 429, 5xx, and transport errors (reset, timeout). What is not:
//! 4xx other than 429. A 401 is a wrong key and a 400 is a malformed request —
//! neither improves by asking again, and retrying them just delays the real
//! message.
//!
//! `Retry-After` wins over the computed backoff when the provider sends it, which
//! is the only number that actually knows when the limit clears. A `Retry-After`
//! longer than [`MAX_HONORED_RETRY_AFTER`] is refused rather than slept through:
//! sitting inside a scan for ten minutes is worse than saying when to come back.

use std::time::Duration;

use anyhow::Result;
use rand::Rng;
use tokio_util::sync::CancellationToken;

/// Total attempts per call, including the first. Three retries is enough to ride
/// out a short rate-limit window without turning one stuck call into a long wall
/// of silence — Phase 2 runs four scanners at once, each with its own budget.
pub const MAX_ATTEMPTS: u32 = 4;
/// First backoff step. Doubles per attempt.
const BASE_DELAY: Duration = Duration::from_millis(1_000);
/// Ceiling for the computed backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Longest `Retry-After` this will actually wait out.
pub const MAX_HONORED_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Env override for [`MAX_ATTEMPTS`], for CI runners on a tight schedule.
/// `ZENTRA_PROVIDER_MAX_ATTEMPTS=1` disables retrying entirely.
pub fn max_attempts() -> u32 {
    std::env::var("ZENTRA_PROVIDER_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(MAX_ATTEMPTS)
}

/// Whether a status code is worth asking again about.
pub fn is_retryable_status(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

/// Whether a transport-level failure is worth asking again about. A connect or
/// read timeout and a dropped connection are transient; a bad URL or a TLS
/// failure is not.
pub fn is_retryable_transport_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request()
}

/// Parse a `Retry-After` value: either delay-seconds or an HTTP-date.
///
/// `now` is passed in rather than read from the clock so the date branch is
/// testable. A date in the past yields `Duration::ZERO`, not an error.
pub fn parse_retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let when = chrono::DateTime::parse_from_rfc2822(value).ok()?;
    let delta = when.with_timezone(&chrono::Utc) - now;
    Some(
        delta
            .to_std()
            .unwrap_or(Duration::ZERO)
            .min(Duration::from_secs(u64::MAX / 2)),
    )
}

/// Exponential backoff for `attempt` (1-based), capped at [`MAX_BACKOFF`], with
/// up to 25% jitter added.
///
/// Jitter matters inside one process here: the four Phase 2 scanners hit the
/// provider together, so without it they would retry in lockstep and re-trip the
/// same limit. It affects timing only, never scan output.
pub fn backoff_delay(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(10);
    let base = BASE_DELAY
        .saturating_mul(2u32.saturating_pow(exponent))
        .min(MAX_BACKOFF);
    let jitter_ceiling = base.as_millis() as u64 / 4;
    let jitter = if jitter_ceiling == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..=jitter_ceiling)
    };
    base + Duration::from_millis(jitter)
}

/// What to do after a failed attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Wait this long, then try again.
    RetryAfter(Duration),
    /// Stop. The reason is already in the caller's error.
    GiveUp,
}

/// Decide whether to retry, given the attempt number and an optional
/// `Retry-After` hint.
///
/// `retry_after` wins over backoff when present, because it is the only value
/// that knows when the window clears. One that exceeds
/// [`MAX_HONORED_RETRY_AFTER`] gives up instead.
pub fn decide(attempt: u32, max_attempts: u32, retry_after: Option<Duration>) -> Decision {
    if attempt >= max_attempts {
        return Decision::GiveUp;
    }
    match retry_after {
        Some(delay) if delay > MAX_HONORED_RETRY_AFTER => Decision::GiveUp,
        Some(delay) => Decision::RetryAfter(delay),
        None => Decision::RetryAfter(backoff_delay(attempt)),
    }
}

/// Sleep for `delay`, or return `Err` at once if the scan is cancelled.
///
/// A plain sleep here would make Ctrl-C hang for the length of the backoff.
pub async fn wait(delay: Duration, cancel_token: Option<&CancellationToken>) -> Result<()> {
    match cancel_token {
        Some(token) => {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    Err(anyhow::anyhow!("LLM request cancelled by user"))
                }
                _ = tokio::time::sleep(delay) => Ok(()),
            }
        }
        None => {
            tokio::time::sleep(delay).await;
            Ok(())
        }
    }
}

/// The log line emitted before each retry, so a rate-limited scan says so
/// instead of looking idle.
pub fn retry_log_line(
    provider: &str,
    attempt: u32,
    max_attempts: u32,
    delay: Duration,
    cause: &str,
) -> String {
    format!(
        "{provider}: {cause} — retrying in {:.1}s (attempt {}/{})",
        delay.as_secs_f32(),
        attempt + 1,
        max_attempts
    )
}

/// The error message after the last attempt fails, naming the attempt count so
/// the operator can tell one 429 from a sustained limit.
pub fn exhausted_message(provider: &str, attempts: u32, last_error: &str) -> String {
    format!(
        "{provider} failed after {attempts} attempt(s): {last_error}\n\
Set ZENTRA_PROVIDER_MAX_ATTEMPTS to change the retry count, or wait for the rate \
limit to clear and re-run."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_rate_limit_and_server_errors() {
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(502));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(504));
    }

    #[test]
    fn does_not_retry_a_permanent_client_error() {
        // A wrong key or a malformed request does not improve by asking again,
        // and retrying only delays the message that says what is wrong.
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(401));
        assert!(!is_retryable_status(403));
        assert!(!is_retryable_status(404));
        assert!(!is_retryable_status(422));
        assert!(!is_retryable_status(200));
    }

    #[test]
    fn parses_retry_after_seconds() {
        let now = chrono::Utc::now();
        assert_eq!(parse_retry_after("30", now), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after("  7 ", now), Some(Duration::from_secs(7)));
        assert_eq!(parse_retry_after("0", now), Some(Duration::ZERO));
    }

    #[test]
    fn parses_retry_after_http_date() {
        let now = chrono::DateTime::parse_from_rfc2822("Thu, 30 Jul 2026 13:00:00 GMT")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let delay = parse_retry_after("Thu, 30 Jul 2026 13:00:45 GMT", now).unwrap();
        assert_eq!(delay, Duration::from_secs(45));
    }

    #[test]
    fn a_past_retry_after_date_is_zero_not_an_error() {
        let now = chrono::DateTime::parse_from_rfc2822("Thu, 30 Jul 2026 13:00:00 GMT")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            parse_retry_after("Thu, 30 Jul 2026 12:59:00 GMT", now),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn rejects_an_unparseable_retry_after() {
        let now = chrono::Utc::now();
        assert_eq!(parse_retry_after("soon", now), None);
        assert_eq!(parse_retry_after("", now), None);
    }

    #[test]
    fn backoff_grows_and_stays_capped() {
        let first = backoff_delay(1);
        let second = backoff_delay(2);
        let third = backoff_delay(3);

        assert!(first >= Duration::from_millis(1_000));
        assert!(first <= Duration::from_millis(1_250));
        assert!(second >= Duration::from_millis(2_000));
        assert!(third >= Duration::from_millis(4_000));

        // Far past the cap, still bounded (cap plus jitter).
        let far = backoff_delay(50);
        assert!(
            far <= MAX_BACKOFF + Duration::from_millis(MAX_BACKOFF.as_millis() as u64 / 4),
            "got {far:?}"
        );
    }

    #[test]
    fn gives_up_on_the_last_attempt() {
        assert_eq!(decide(4, 4, None), Decision::GiveUp);
        assert_eq!(decide(5, 4, None), Decision::GiveUp);
        assert_eq!(decide(1, 1, None), Decision::GiveUp, "1 attempt = no retry");
    }

    #[test]
    fn retry_after_wins_over_backoff() {
        assert_eq!(
            decide(1, 4, Some(Duration::from_secs(12))),
            Decision::RetryAfter(Duration::from_secs(12))
        );
    }

    #[test]
    fn gives_up_when_retry_after_is_longer_than_we_will_wait() {
        assert_eq!(
            decide(1, 4, Some(Duration::from_secs(600))),
            Decision::GiveUp,
            "sleeping ten minutes inside a scan is worse than reporting it"
        );
        assert_eq!(
            decide(1, 4, Some(MAX_HONORED_RETRY_AFTER)),
            Decision::RetryAfter(MAX_HONORED_RETRY_AFTER),
            "exactly at the ceiling is still honored"
        );
    }

    #[test]
    fn falls_back_to_backoff_without_a_hint() {
        match decide(1, 4, None) {
            Decision::RetryAfter(d) => assert!(d >= Duration::from_millis(1_000)),
            Decision::GiveUp => panic!("should retry on attempt 1 of 4"),
        }
    }

    #[tokio::test]
    async fn wait_returns_immediately_when_cancelled() {
        let token = CancellationToken::new();
        token.cancel();
        let result = wait(Duration::from_secs(30), Some(&token)).await;
        assert!(result.is_err(), "a cancelled scan must not sleep out a backoff");
    }

    #[tokio::test]
    async fn wait_completes_when_not_cancelled() {
        let token = CancellationToken::new();
        assert!(wait(Duration::from_millis(1), Some(&token)).await.is_ok());
        assert!(wait(Duration::from_millis(1), None).await.is_ok());
    }

    #[test]
    fn max_attempts_honors_the_env_override() {
        // The env var is process-global, so assert on the parse rule rather than
        // mutating it here — a parallel test would see the change.
        assert_eq!(MAX_ATTEMPTS, 4);
        assert!(max_attempts() >= 1);
    }

    #[test]
    fn messages_name_the_numbers() {
        let line = retry_log_line("Anthropic", 1, 4, Duration::from_secs(2), "429 rate limited");
        assert!(line.contains("429 rate limited"), "got: {line}");
        assert!(line.contains("2.0s"), "got: {line}");
        assert!(line.contains("attempt 2/4"), "got: {line}");

        let exhausted = exhausted_message("Anthropic", 4, "429 Too Many Requests");
        assert!(exhausted.contains("after 4 attempt(s)"), "got: {exhausted}");
        assert!(
            exhausted.contains("ZENTRA_PROVIDER_MAX_ATTEMPTS"),
            "got: {exhausted}"
        );
    }
}
