pub(crate) fn is_valid_domain_name(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::is_valid_domain_name;

    #[test]
    fn test_is_valid_domain_name_accepts_standard_domains() {
        assert!(is_valid_domain_name("example.com"));
        assert!(is_valid_domain_name("a-b.example.net"));
        assert!(is_valid_domain_name("localhost"));
    }

    #[test]
    fn test_is_valid_domain_name_rejects_invalid_domains() {
        assert!(!is_valid_domain_name(""));
        assert!(!is_valid_domain_name(".example.com"));
        assert!(!is_valid_domain_name("example.com."));
        assert!(!is_valid_domain_name("exa_mple.com"));
        assert!(!is_valid_domain_name("-example.com"));
        assert!(!is_valid_domain_name("example-.com"));
        assert!(!is_valid_domain_name("exa*mple.com"));
    }
}
