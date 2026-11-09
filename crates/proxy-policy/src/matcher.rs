//! Path matching with traversal bypass prevention.
//!
//! Paths are normalized before matching to defeat `..` and `.` traversal.
//! Matching is segment-wise:
//!
//! - `/exact/path` matches only `/exact/path`
//! - `/prefix/*` matches `/prefix/anything` (one segment)
//! - `/prefix/**` matches `/prefix/a/b/c` (any depth)
//! - `/**` matches everything

/// Normalize a URL path to prevent traversal attacks.
///
/// Resolves `.` and `..` segments, collapses multiple slashes, and ensures
/// the result starts with `/`.
pub fn normalize_path(path: &str) -> String {
    let path = decode_encoded_separators(path);
    let mut segments: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }

    if segments.is_empty() {
        return "/".to_string();
    }

    format!("/{}", segments.join("/"))
}

fn decode_encoded_separators(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                let value = high * 16 + low;
                if matches!(value, b'.' | b'/' | b'\\') {
                    decoded.push(if value == b'\\' { b'/' } else { value });
                    index += 3;
                    continue;
                }
            }
        }

        decoded.push(bytes[index]);
        index += 1;
    }

    String::from_utf8(decoded).expect("decoding ASCII path delimiters preserves UTF-8")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Check if a request path matches a policy path pattern.
///
/// Both paths are normalized before comparison.
pub fn path_matches(pattern: &str, request_path: &str) -> bool {
    let norm_pattern = normalize_path(pattern);
    let norm_path = normalize_path(request_path);

    let pattern_segments: Vec<&str> = norm_pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segments: Vec<&str> = norm_path.split('/').filter(|s| !s.is_empty()).collect();

    match_segments(&pattern_segments, &path_segments)
}

fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (Some(&"**"), _) => true,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (Some(&"*"), Some(_)) => match_segments(&pattern[1..], &path[1..]),
        (Some(p), Some(r)) if p == r => match_segments(&pattern[1..], &path[1..]),
        _ => false,
    }
}

/// Check if an identity string matches a policy identity pattern.
pub fn identity_matches(pattern: &str, identity: &str) -> bool {
    if pattern == "**" || pattern == "*" {
        return true;
    }

    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let identity_parts: Vec<&str> = identity.split('/').collect();

    match_identity_parts(&pattern_parts, &identity_parts)
}

fn match_identity_parts(pattern: &[&str], identity: &[&str]) -> bool {
    match (pattern.first(), identity.first()) {
        (None, None) => true,
        (Some(&"**"), _) => true,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (Some(&"*"), Some(_)) => match_identity_parts(&pattern[1..], &identity[1..]),
        (Some(p), Some(i)) if p == i => match_identity_parts(&pattern[1..], &identity[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_basic() {
        assert_eq!(normalize_path("/api/v1/users"), "/api/v1/users");
    }

    #[test]
    fn normalize_traversal() {
        assert_eq!(normalize_path("/api/v1/../admin"), "/api/admin");
    }

    #[test]
    fn normalize_encoded_traversal_and_separators() {
        assert_eq!(
            normalize_path("/api/v1/identity/%2e%2e/%2E%2e/admin"),
            "/api/admin"
        );
        assert_eq!(normalize_path("/api%2fv1%5cidentity"), "/api/v1/identity");
    }

    #[test]
    fn normalize_double_dot_at_root() {
        assert_eq!(normalize_path("/../../../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn normalize_dot_segments() {
        assert_eq!(normalize_path("/api/./v1/./users"), "/api/v1/users");
    }

    #[test]
    fn normalize_empty() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn normalize_multiple_slashes() {
        assert_eq!(normalize_path("//api///v1//"), "/api/v1");
    }

    #[test]
    fn path_exact_match() {
        assert!(path_matches("/api/v1/health", "/api/v1/health"));
        assert!(!path_matches("/api/v1/health", "/api/v1/users"));
    }

    #[test]
    fn path_single_wildcard() {
        assert!(path_matches("/api/v1/*", "/api/v1/users"));
        assert!(!path_matches("/api/v1/*", "/api/v1/users/123"));
    }

    #[test]
    fn path_double_wildcard() {
        assert!(path_matches("/api/**", "/api/v1/users/123"));
        assert!(path_matches("/api/**", "/api/health"));
        assert!(!path_matches("/api/**", "/other/path"));
    }

    #[test]
    fn path_traversal_defeated() {
        assert!(!path_matches("/api/**", "/api/../admin/secret"));
    }

    #[test]
    fn identity_spiffe_wildcard() {
        assert!(identity_matches(
            "spiffe://arkion.internal/agent/*",
            "spiffe://arkion.internal/agent/42"
        ));
        assert!(!identity_matches(
            "spiffe://arkion.internal/agent/*",
            "spiffe://arkion.internal/gateway/ai"
        ));
    }

    #[test]
    fn identity_exact_match() {
        assert!(identity_matches("CN=admin", "CN=admin"));
        assert!(!identity_matches("CN=admin", "CN=user"));
    }

    #[test]
    fn identity_catch_all() {
        assert!(identity_matches("**", "anything/at/all"));
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn normalize_is_idempotent(path in "/[a-z/..]{0,50}") {
                let once = normalize_path(&path);
                let twice = normalize_path(&once);
                prop_assert_eq!(once, twice);
            }

            #[test]
            fn normalize_never_contains_dotdot(path in "/[a-z/..]{0,50}") {
                let norm = normalize_path(&path);
                prop_assert!(norm.split('/').all(|segment| segment != "." && segment != ".."));
            }

            #[test]
            fn normalize_always_starts_with_slash(path in "[a-z/..]{0,50}") {
                let norm = normalize_path(&path);
                prop_assert!(norm.starts_with("/"));
            }
        }
    }
}
