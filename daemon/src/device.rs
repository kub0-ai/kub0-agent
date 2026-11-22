//! The kub0 device-code login, as a library: the daemon runs it when it
//! answers a `kub0 login` request (the daemon's own `connect` verb is retired).

use std::time::{Duration, Instant};

/// Device codes one login mints before it gives up. A code lives
/// `expires_in` seconds (900 at kub0.ai), so four codes keep the terminal or
/// the panel usable for an hour. Until 2026-10-31 the command exited on the
/// first expiry and the operator re-ran it from a shell loop to have a code
/// on screen when they reached the browser.
pub const MAX_CODES: u32 = 4;

/// One minted device code, as `POST /api/auth/device/start` returned it.
#[derive(Debug, Clone)]
pub struct DeviceCode {
    pub device_state: String,
    pub user_code: String,
    pub connect_url: String,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Clone)]
pub enum DevicePoll {
    Expired,
    Complete { token: String, github_username: String },
}

pub fn http_agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(crate::kub0::HTTP_TIMEOUT_SECS)))
            .http_status_as_error(false)
            .build(),
    )
}

pub fn device_start(agent: &ureq::Agent, auth_url: &str) -> Result<DeviceCode, String> {
    let start_url = format!("{}/api/auth/device/start", auth_url.trim_end_matches('/'));
    let mut start_resp = agent
        .post(&start_url)
        .send_empty()
        .map_err(|e| format!("device start failed: {e}"))?;
    let start_status = start_resp.status().as_u16();
    if start_status != 200 {
        return Err(format!("device start failed (HTTP {start_status})"));
    }
    let start: serde_json::Value = start_resp
        .body_mut()
        .read_json()
        .map_err(|e| format!("device start: bad JSON: {e}"))?;
    let field = |name: &str| -> Result<String, String> {
        start
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("device start: missing {name}"))
    };
    Ok(DeviceCode {
        device_state: field("device_state")?,
        user_code: field("user_code")?,
        connect_url: field("connect_url")?,
        expires_in: start
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(900),
        interval: start
            .get("interval")
            .and_then(|v| v.as_u64())
            .unwrap_or(5)
            .max(1),
    })
}

/// Polls one code until the browser completes it or it expires. A transport
/// error is logged and retried; the code's own lifetime bounds the loop.
/// `cancelled` is consulted between polls so a daemon can abandon a login
/// whose client has gone.
pub fn device_poll(
    agent: &ureq::Agent,
    auth_url: &str,
    code: &DeviceCode,
    cancelled: &dyn Fn() -> bool,
) -> Result<DevicePoll, String> {
    let poll_url = format!("{}/api/auth/device/poll", auth_url.trim_end_matches('/'));
    let deadline = Instant::now() + Duration::from_secs(code.expires_in);
    loop {
        if Instant::now() >= deadline {
            return Ok(DevicePoll::Expired);
        }
        // Sleep in slices so a cancellation is seen within a second.
        let wake = Instant::now() + Duration::from_secs(code.interval);
        while let Some(left) = wake.checked_duration_since(Instant::now()) {
            if cancelled() {
                return Err("login cancelled".into());
            }
            std::thread::sleep(left.min(Duration::from_millis(500)));
        }
        let mut poll_resp = match agent
            .get(&poll_url)
            .query("state", &code.device_state)
            .call()
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("kub0d: device login poll error: {e}");
                continue;
            }
        };
        let http_status = poll_resp.status().as_u16();
        let body: serde_json::Value = poll_resp
            .body_mut()
            .read_json()
            .unwrap_or(serde_json::Value::Null);
        let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if http_status == 404 || status == "expired" {
            return Ok(DevicePoll::Expired);
        }
        if status == "complete" {
            let token = body
                .get("token")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| "device poll: complete without token".to_string())?;
            let github_username = body
                .get("github_username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return Ok(DevicePoll::Complete {
                token,
                github_username,
            });
        }
    }
}
