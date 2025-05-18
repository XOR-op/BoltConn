use russh::compression;

pub(crate) fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    let session_start = 5 + 4 + 2 + 32;
    // TLS && ClientHello && packet length matches
    if !(buf.len() > session_start
        && buf[0] == 0x16
        && buf[5] == 0x01
        && ((((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize) + 9)
            == buf.len())
    {
        return None;
    }
    let cipher_start = skip_part(buf, session_start, 1)?;
    let compression_start = skip_part(buf, cipher_start, 2)?;
    let mut ext_entry = skip_part(buf, compression_start, 1)? + 2;
    while ext_entry + 2 < buf.len() {
        let ext_type = parse_two_bytes(buf, ext_entry)?;
        // SNI extension
        if ext_type == 0x0000 {
            let sni_name_start = ext_entry + 9;
            if sni_name_start >= buf.len() {
                return None;
            }
            let sni_type = buf[ext_entry + 6];
            let sni_len = parse_two_bytes(buf, ext_entry + 7)?;
            // DNS record
            if sni_type == 0x00 && sni_len > 0 && sni_name_start + sni_len <= buf.len() {
                let sni_name = &buf[sni_name_start..sni_name_start + sni_len];
                if let Ok(sni) = String::from_utf8(sni_name.to_vec()) {
                    return Some(sni);
                }
            }
            return None;
        }
        // skip to next extension
        ext_entry = skip_part(buf, ext_entry + 2, 2)?;
    }
    None
}

#[inline]
fn skip_part(buf: &[u8], idx_start: usize, len_size: usize) -> Option<usize> {
    if len_size > 4 || idx_start + len_size >= buf.len() {
        return None;
    }
    let big_endian = {
        let mut size = 0;
        for i in 0..len_size {
            size <<= 8;
            size |= buf[idx_start + i] as usize;
        }
        size
    };
    let next_start = idx_start + big_endian + len_size;
    if next_start > buf.len() {
        return None;
    } else {
        Some(next_start)
    }
}

#[inline]
fn parse_two_bytes(buf: &[u8], idx_start: usize) -> Option<usize> {
    if idx_start + 2 >= buf.len() {
        return None;
    }
    let size = ((buf[idx_start] as usize) << 8) | (buf[idx_start + 1] as usize);
    Some(size)
}

// only parse if host is in the second line now
pub(crate) fn parse_http_host(buf: &[u8]) -> Option<String> {
    // [idx_start..idx_end)
    let idx_start = {
        let idx = find_crlf(buf, 0)?;
        if idx + 2 < buf.len() {
            idx + 2
        } else {
            return None;
        }
    };
    let idx_end = find_crlf(buf, idx_start)?;

    // scan host field
    let content = String::from_utf8_lossy(&buf[idx_start..idx_end]).to_ascii_lowercase();
    if content.starts_with("host: ") {
        // skip port if present
        Some(
            content[6..]
                .trim()
                .split(':')
                .next()
                .expect("at least 1 entry")
                .to_string(),
        )
    } else {
        None
    }
}

#[inline]
fn find_crlf(buf: &[u8], idx_start: usize) -> Option<usize> {
    for i in idx_start..buf.len() {
        if buf[i] == b'\r' && i + 1 < buf.len() && buf[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls_sni() {}

    #[test]
    fn test_parse_http_host() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_http_host(buf), Some("example.com".to_string()));
        let buf = b"GET / HTTP/1.1\r\nHost: www.example.org:8080\r\nCookie: x-1C38F78AA123\r\n\r\n";
        assert_eq!(parse_http_host(buf), Some("www.example.org".to_string()));
        let buf = b"GET / HTTP/1.1\r\nHi: example.com\r\n\r\n";
        assert_eq!(parse_http_host(buf), None);
    }
}
