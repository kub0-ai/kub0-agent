//! Verify a complete `socket cgroupv2 level N <path> drop` rule.
//! Prefers nft JSON (`nft -j`); text listing is the fallback.

use serde_json::Value;

pub fn cgroup_drop_in_json(json_text: &str, path: &str, level: u32) -> bool {
    let v: Value = match serde_json::from_str(json_text) {
        Ok(v) => v,
        Err(_) => return false,
    };
    find_matching_rule(&v, path, level)
}

pub fn cgroup_drop_in_text(text: &str, path: &str, level: u32) -> bool {
    for line in text.lines() {
        if line_is_cgroup_drop(line, path, level) {
            return true;
        }
    }
    false
}

fn line_is_cgroup_drop(line: &str, path: &str, level: u32) -> bool {
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == "comment" && words.next().is_some_and(|s| s.trim_matches('"') == "vallum-scoped") { return false; }
    }
    cgroup_drop_any_in_text(line, path, level)
}

/// Cleanup matches both scoped and whole-app drops. Classification deliberately
/// excludes scoped comments, but deletion must remove them before their sets.
pub fn cgroup_drop_any_in_text(text: &str, path: &str, level: u32) -> bool {
    text.lines().any(|line| line_is_any_cgroup_drop(line, path, level))
}

fn line_is_any_cgroup_drop(line: &str, path: &str, level: u32) -> bool {
    if !line_has_path(line, path) {
        return false;
    }
    let l = line.to_ascii_lowercase();
    if !l.contains("socket") || !l.contains("cgroupv2") {
        return false;
    }
    if !l.contains(&format!("level {level}")) && !l.contains(&format!("level{level}")) {
        return false;
    }
    l.split_whitespace().any(|t| t == "drop")
}

fn line_has_path(line: &str, path: &str) -> bool {
    line.split_whitespace().any(|t| t.trim_matches('"') == path)
}

fn find_matching_rule(v: &Value, path: &str, level: u32) -> bool {
    match v {
        Value::Object(map) => {
            if let Some(rule) = map.get("rule") {
                if rule_is_cgroup_drop(rule, path, level) {
                    return true;
                }
            }
            if map.contains_key("expr") && rule_is_cgroup_drop(v, path, level) {
                return true;
            }
            map.values().any(|child| find_matching_rule(child, path, level))
        }
        Value::Array(arr) => arr.iter().any(|child| find_matching_rule(child, path, level)),
        _ => false,
    }
}

fn rule_is_cgroup_drop(rule: &Value, path: &str, level: u32) -> bool {
    if rule.get("comment").and_then(Value::as_str) == Some("vallum-scoped") {
        return false;
    }
    let exprs = match rule.get("expr").and_then(|e| e.as_array()) {
        Some(a) => a,
        None => return false,
    };
    let has_drop = exprs.iter().any(expr_is_drop);
    let has_match = exprs.iter().any(|e| expr_is_cgroup_match(e, path, level));
    has_drop && has_match
}

fn expr_is_drop(e: &Value) -> bool {
    match e {
        Value::String(s) => s.eq_ignore_ascii_case("drop"),
        Value::Object(m) => {
            if m.contains_key("drop") {
                return true;
            }
            match m.get("verdict") {
                Some(Value::String(s)) => s.eq_ignore_ascii_case("drop"),
                Some(Value::Object(o)) => {
                    o.contains_key("drop")
                        || o.get("type")
                            .and_then(|t| t.as_str())
                            .is_some_and(|t| t.eq_ignore_ascii_case("drop"))
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn expr_is_cgroup_match(e: &Value, path: &str, level: u32) -> bool {
    json_has_exact_string(e, path) && socket_cgroup_level(e, level)
}

fn json_has_exact_string(v: &Value, s: &str) -> bool {
    match v {
        Value::String(t) => t == s,
        Value::Object(m) => m.values().any(|c| json_has_exact_string(c, s)),
        Value::Array(a) => a.iter().any(|c| json_has_exact_string(c, s)),
        _ => false,
    }
}

fn socket_cgroup_level(v: &Value, level: u32) -> bool {
    match v {
        Value::Object(m) => {
            if let Some(sock) = m.get("socket") {
                if socket_obj_matches(sock, level) {
                    return true;
                }
            }
            m.values().any(|c| socket_cgroup_level(c, level))
        }
        Value::Array(a) => a.iter().any(|c| socket_cgroup_level(c, level)),
        _ => false,
    }
}

fn socket_obj_matches(sock: &Value, level: u32) -> bool {
    let Some(obj) = sock.as_object() else {
        return false;
    };
    let is_cgroup = obj.get("key").and_then(|k| k.as_str()) == Some("cgroupv2")
        || obj.contains_key("cgroupv2")
        || obj.values().any(|v| {
            v.as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("cgroupv2"))
        });
    if !is_cgroup {
        return false;
    }
    let lvl = obj
        .get("field")
        .and_then(|f| f.as_u64())
        .or_else(|| obj.get("level").and_then(|f| f.as_u64()))
        .or_else(|| {
            obj.get("cgroupv2")
                .and_then(|c| c.get("level").or_else(|| c.get("field")))
                .and_then(|f| f.as_u64())
        });
    lvl == Some(u64::from(level))
}

/// The elements of one set, from `nft list set` text output.
///
/// Membership used to be a substring test on that text, so `1.2.3.4` was
/// "present" whenever `11.2.3.44` was, and an unblock could report failure for
/// an address it had in fact removed. This returns whole elements to compare
/// exactly. nft wraps long sets across lines and may annotate an element
/// (`1.2.3.4 timeout 1h`); only the address token is kept.
pub fn set_elements_in_text(text: &str) -> Vec<String> {
    let Some(start) = text.find("elements = {") else {
        return Vec::new();
    };
    let body = &text[start + "elements = {".len()..];
    let body = &body[..body.find('}').unwrap_or(body.len())];
    body.split(',')
        .filter_map(|e| e.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Every app with a live cgroup drop rule in a table listing, by the id the
/// helper stored it under (the part after `vallum.slice/vallum-`).
///
/// The panel keeps its idea of what is blocked in memory, so after a shell
/// restart it believed nothing was, while these rules went on enforcing.
/// `status` reports this list so the panel can put the blocks back.
pub fn cgroup_blocked_apps(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        for tok in line.split_whitespace() {
            let path = tok.trim_matches('"');
            let Some(app) = path.strip_prefix("vallum.slice/vallum-") else {
                continue;
            };
            if app.is_empty() || app.contains('/') {
                continue;
            }
            if line_is_cgroup_drop(line, path, 2) && !out.iter().any(|a| a == app) {
                out.push(app.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "vallum.slice/vallum-firefox";

    fn json_key_field() -> String {
        format!(
            r#"{{"nftables":[{{"rule":{{"family":"inet","table":"vallum","chain":"out","expr":[
                {{"match":{{"op":"==","left":{{"socket":{{"key":"cgroupv2","field":2}}}},"right":"{PATH}"}}}},
                {{"drop":null}}
            ]}}}}]}}"#
        )
    }

    fn json_nested_level() -> String {
        format!(
            r#"{{"nftables":[{{"rule":{{"expr":[
                {{"match":{{"left":{{"socket":{{"cgroupv2":{{"level":2}}}}}},"right":"{PATH}"}}}},
                {{"verdict":{{"drop":null}}}}
            ]}}}}]}}"#
        )
    }

    #[test]
    fn json_key_field_drop_matches() {
        assert!(cgroup_drop_in_json(&json_key_field(), PATH, 2));
    }

    #[test]
    fn scoped_drops_do_not_claim_the_entire_app_is_blocked() {
        let scoped=json_key_field().replace("\"expr\":", "\"comment\":\"vallum-scoped\",\"expr\":");
        assert!(!cgroup_drop_in_json(&scoped,PATH,2));
        assert!(!cgroup_drop_in_text(&format!("socket cgroupv2 level 2 \"{PATH}\" ip daddr @t4 drop comment \"vallum-scoped\""),PATH,2));
        assert!(cgroup_blocked_apps(&format!("socket cgroupv2 level 2 \"{PATH}\" ip daddr @t4 drop comment \"vallum-scoped\"" )).is_empty());
        assert!(cgroup_drop_any_in_text(&format!("socket cgroupv2 level 2 \"{PATH}\" ip daddr @t4 drop comment \"vallum-scoped\""), PATH, 2));
        let named = "vallum.slice/vallum-org.vallum-scoped";
        assert!(cgroup_drop_in_text(&format!("socket cgroupv2 level 2 \"{named}\" drop"), named, 2));
    }

    #[test]
    fn json_nested_level_drop_matches() {
        assert!(cgroup_drop_in_json(&json_nested_level(), PATH, 2));
    }

    #[test]
    fn json_wrong_level_rejected() {
        assert!(!cgroup_drop_in_json(&json_key_field(), PATH, 1));
    }

    #[test]
    fn json_accept_instead_of_drop_rejected() {
        let js = format!(
            r#"{{"nftables":[{{"rule":{{"expr":[
                {{"match":{{"left":{{"socket":{{"key":"cgroupv2","field":2}}}},"right":"{PATH}"}}}},
                {{"accept":null}}
            ]}}}}]}}"#
        );
        assert!(!cgroup_drop_in_json(&js, PATH, 2));
    }

    #[test]
    fn text_prefix_path_is_not_a_match() {
        let line = r#"socket cgroupv2 level 2 "vallum.slice/vallum-firefox2" drop # handle 12"#;
        assert!(!cgroup_drop_in_text(line, "vallum.slice/vallum-firefox", 2));
        assert!(cgroup_drop_in_text(line, "vallum.slice/vallum-firefox2", 2));
    }

    #[test]
    fn json_path_on_one_rule_drop_on_another_rejected() {
        let js = format!(
            r#"{{"nftables":[
              {{"rule":{{"expr":[
                {{"match":{{"left":{{"socket":{{"key":"cgroupv2","field":2}}}},"right":"{PATH}"}}}},
                {{"accept":null}}
              ]}}}},
              {{"rule":{{"expr":[
                {{"match":{{"left":{{"payload":{{"protocol":"ip","field":"daddr"}}}},"right":"1.2.3.4"}}}},
                {{"drop":null}}
              ]}}}}
            ]}}"#
        );
        assert!(!cgroup_drop_in_json(&js, PATH, 2));
    }

    #[test]
    fn json_prefix_path_does_not_match() {
        assert!(!cgroup_drop_in_json(
            &json_key_field(),
            "vallum.slice/vallum-fire",
            2
        ));
    }

    #[test]
    fn text_quoted_rule_matches() {
        let text = r#"
table inet vallum {
	chain out {
		socket cgroupv2 level 2 "vallum.slice/vallum-firefox" drop
	}
}
"#;
        assert!(cgroup_drop_in_text(text, PATH, 2));
        assert!(!cgroup_drop_in_text(text, PATH, 3));
        assert!(!cgroup_drop_in_text(text, "vallum.slice/vallum-fire", 2));
    }

    #[test]
    fn text_accept_rejected() {
        let text = r#"        socket cgroupv2 level 2 "vallum.slice/vallum-firefox" accept"#;
        assert!(!cgroup_drop_in_text(text, PATH, 2));
    }

    #[test]
    fn set_elements_are_whole_addresses_not_substrings() {
        let text = "table inet vallum {\n\tset blocked4 {\n\t\ttype ipv4_addr\n\t\telements = { 11.2.3.44, 93.184.216.34,\n\t\t\t     10.0.0.1 timeout 1h }\n\t}\n}\n";
        let els = set_elements_in_text(text);
        assert_eq!(els, ["11.2.3.44", "93.184.216.34", "10.0.0.1"]);
        assert!(!els.iter().any(|e| e == "1.2.3.4"));
        assert!(set_elements_in_text("table inet vallum {\n\tset blocked4 {\n\t}\n}").is_empty());
        let v6 = "\t\telements = { 2001:db8::1, ::ffff:1.2.3.4 }";
        assert_eq!(set_elements_in_text(v6), ["2001:db8::1", "::ffff:1.2.3.4"]);
    }

    #[test]
    fn blocked_apps_are_read_from_live_drop_rules_only() {
        let text = r#"table inet vallum {
	chain out {
		type filter hook output priority filter; policy accept;
		socket cgroupv2 level 2 "vallum.slice/vallum-com.discordapp.discord" drop # handle 7
		socket cgroupv2 level 2 "vallum.slice/vallum-firefox" drop # handle 9
		socket cgroupv2 level 2 "vallum.slice/vallum-firefox" drop # handle 12
		socket cgroupv2 level 2 "vallum.slice/vallum-counted" counter packets 0 bytes 0 accept # handle 13
		ip daddr @blocked4 drop # handle 4
	}
}"#;
        assert_eq!(cgroup_blocked_apps(text), ["com.discordapp.discord", "firefox"]);
        assert!(cgroup_blocked_apps("").is_empty());
    }
}
