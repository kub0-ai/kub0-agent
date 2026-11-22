//! Plain text output. Labels and columns, no colour, nothing a pipe would
//! trip over.

/// `label: value` rows, labels padded to the widest.
pub fn kv(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (k, v) in rows {
        out.push_str(&format!("{k:<width$}  {v}\n"));
    }
    out
}

/// A table with a header row. Columns are left-aligned and padded to the
/// widest cell; the last column is never padded, so a wide path does not
/// trail spaces.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: &[String]| -> String {
        let mut s = String::new();
        for i in 0..cols {
            let cell = cells.get(i).map(String::as_str).unwrap_or("");
            if i + 1 == cols {
                s.push_str(cell);
            } else {
                let pad = widths[i].saturating_sub(cell.chars().count());
                s.push_str(cell);
                s.extend(std::iter::repeat(' ').take(pad + 2));
            }
        }
        s.trim_end().to_string() + "\n"
    };
    let mut out = line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    for row in rows {
        out.push_str(&line(row));
    }
    out
}

pub fn yes_no(b: bool) -> String {
    if b { "yes".into() } else { "no".into() }
}

pub fn opt_bool(v: Option<bool>) -> String {
    match v {
        Some(true) => "yes".into(),
        Some(false) => "no".into(),
        None => "unknown".into(),
    }
}

/// Seconds as `3d 4h`, `4h 05m`, `5m 09s` or `9s`.
pub fn duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, (secs / 3_600) % 24, (secs / 60) % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {s:02}s")
    } else {
        format!("{s}s")
    }
}

/// A unix-ms timestamp as how long ago, or `never` for zero.
pub fn ago(ts_ms: u64, now_ms: u64) -> String {
    if ts_ms == 0 {
        return "never".into();
    }
    let secs = now_ms.saturating_sub(ts_ms) / 1000;
    format!("{} ago", duration(secs))
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A JSON value as a cell: strings bare, the rest compact JSON, null empty.
pub fn cell(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_pads_labels() {
        let s = kv(&[("a", "1".into()), ("long", "2".into())]);
        assert_eq!(s, "a     1\nlong  2\n");
    }

    #[test]
    fn table_pads_all_but_the_last_column() {
        let s = table(&["n", "path"], &[vec!["ab".into(), "/x".into()], vec!["c".into(), "/longer".into()]]);
        assert_eq!(s, "n   path\nab  /x\nc   /longer\n");
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration(9), "9s");
        assert_eq!(duration(309), "5m 09s");
        assert_eq!(duration(3_900), "1h 05m");
        assert_eq!(duration(90_000), "1d 1h");
        assert_eq!(ago(0, 10), "never");
        assert_eq!(ago(1_000, 10_000), "9s ago");
    }

    #[test]
    fn cells_show_strings_bare() {
        assert_eq!(cell(&serde_json::json!("x")), "x");
        assert_eq!(cell(&serde_json::json!(null)), "");
        assert_eq!(cell(&serde_json::json!([1, 2])), "[1,2]");
    }
}
