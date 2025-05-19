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
        None
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
    content.strip_prefix("host: ").map(|c| {
        // skip port if present
        c.trim()
            .split(':')
            .next()
            .expect("at least 1 entry")
            .to_string()
    })
}

#[inline]
fn find_crlf(buf: &[u8], idx_start: usize) -> Option<usize> {
    (idx_start..buf.len()).find(|&i| buf[i] == b'\r' && i + 1 < buf.len() && buf[i + 1] == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls_sni() {
        let data = b"\x16\x03\x01\x00\xf8\x01\x00\x00\xf4\x03\x03\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00\x08\x13\x02\x13\x03\x13\x01\x00\xff\x01\x00\x00\xa3\x00\x00\x00\x18\x00\x16\x00\x00\x13\x65\x78\x61\x6d\x70\x6c\x65\x2e\x75\x6c\x66\x68\x65\x69\x6d\x2e\x6e\x65\x74\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x16\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x23\x00\x00\x00\x16\x00\x00\x00\x17\x00\x00\x00\x0d\x00\x1e\x00\x1c\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x00\x2b\x00\x03\x02\x03\x04\x00\x2d\x00\x02\x01\x01\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20\x35\x80\x72\xd6\x36\x58\x80\xd1\xae\xea\x32\x9a\xdf\x91\x21\x38\x38\x51\xed\x21\xa2\x8e\x3b\x75\xe9\x65\xd0\xd2\xcd\x16\x62\x54";
        assert_eq!(parse_tls_sni(data), Some("example.ulfheim.net".to_string()));
        let data = b"\
        \x16\x03\x01\x00\xeb\x01\x00\x00\xe7\x03\x03\xb6\x1f\xe4\x3a\x55\
        \x90\x3e\xc0\x28\x9c\x12\xe0\x5c\x84\xea\x90\x1b\xfb\x11\xfc\xbd\
        \x25\x55\xda\x9f\x51\x93\x1b\x8d\x92\x66\xfd\x00\x00\x2e\xc0\x2c\
        \xc0\x2b\xc0\x24\xc0\x23\xc0\x0a\xc0\x09\xcc\xa9\xc0\x30\xc0\x2f\
        \xc0\x28\xc0\x27\xc0\x14\xc0\x13\xcc\xa8\x00\x9d\x00\x9c\x00\x3d\
        \x00\x3c\x00\x35\x00\x2f\xc0\x08\xc0\x12\x00\x0a\x01\x00\x00\x90\
        \xff\x01\x00\x01\x00\x00\x00\x00\x0e\x00\x0c\x00\x00\x09\x31\x32\
        \x37\x2e\x30\x2e\x30\x2e\x31\x00\x17\x00\x00\x00\x0d\x00\x18\x00\
        \x16\x04\x03\x08\x04\x04\x01\x05\x03\x02\x03\x08\x05\x08\x05\x05\
        \x01\x08\x06\x06\x01\x02\x01\x00\x05\x00\x05\x01\x00\x00\x00\x00\
        \x33\x74\x00\x00\x00\x12\x00\x00\x00\x10\x00\x30\x00\x2e\x02\x68\
        \x32\x05\x68\x32\x2d\x31\x36\x05\x68\x32\x2d\x31\x35\x05\x68\x32\
        \x2d\x31\x34\x08\x73\x70\x64\x79\x2f\x33\x2e\x31\x06\x73\x70\x64\
        \x79\x2f\x33\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x0b\x00\x02\
        \x01\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19";
        assert_eq!(parse_tls_sni(data), Some("127.0.0.1".to_string()));
    }

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
