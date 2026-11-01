//! Full TCP checksum calculation for the TUN NAT path.
//!
//! Sum native-endian 32-bit words into a wide accumulator. Carries are folded
//! only at the end, allowing the compiler to vectorize the payload scan. This
//! retains full recomputation, including for zero or partial input checksums.

use smoltcp::wire::{IpAddress, IpProtocol, TcpPacket};

fn fold(mut sum: u64) -> u16 {
    sum = (sum & 0xffff_ffff) + (sum >> 32);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u16) + (sum >> 16) as u16
}

fn data_sum(data: &[u8]) -> u16 {
    // An IP packet is at most 65535 bytes here, so summing 32-bit words in
    // u64 cannot overflow. Native-endian loads also work on unaligned slices.
    let mut sum = 0u64;
    let (words, tail) = data.as_chunks::<4>();
    for word in words {
        sum += u32::from_ne_bytes(*word) as u64;
    }
    if !tail.is_empty() {
        let mut word = [0; 4];
        word[..tail.len()].copy_from_slice(tail);
        sum += u32::from_ne_bytes(word) as u64;
    }
    // Folding in native endian is equivalent to summing network-endian words,
    // up to a byte swap of the final 16-bit result on little-endian machines.
    fold(sum).to_be()
}

pub(super) fn fill_tcp_checksum(data: &mut [u8], src: &IpAddress, dst: &IpAddress) {
    let address_sum = match (src, dst) {
        (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
            data_sum(&src.octets()) as u64 + data_sum(&dst.octets()) as u64
        }
        (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
            data_sum(&src.octets()) as u64 + data_sum(&dst.octets()) as u64
        }
        _ => unreachable!("TCP addresses must have the same IP version"),
    };
    let len = data.len() as u64;
    let pseudo_sum = address_sum + u8::from(IpProtocol::Tcp) as u64 + (len >> 16) + (len & 0xffff);
    TcpPacket::new_unchecked(&mut *data).set_checksum(0);
    let checksum = !fold(pseudo_sum + data_sum(data) as u64);
    TcpPacket::new_unchecked(data).set_checksum(checksum);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_sum(data: &[u8]) -> u16 {
        // Independent byte-pair oracle, folding every addition.
        let mut sum = 0u32;
        for word in data.chunks(2) {
            sum += ((word[0] as u32) << 8) | word.get(1).copied().unwrap_or(0) as u32;
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    #[test]
    fn data_sum_matches_byte_pairs_for_lengths_and_alignments() {
        let mut rng = fastrand::Rng::with_seed(0x5eed);
        let mut buffer = vec![0; 65535 + 16];
        rng.fill(&mut buffer);
        // Cover every small tail / vectorization boundary, larger packets,
        // and all source alignments without requiring aligned loads.
        for offset in 0..16 {
            for len in (0..=513).chain([1499, 1500, 1501, 8999, 9000, 9001, 65534, 65535]) {
                let data = &buffer[offset..offset + len];
                assert_eq!(
                    data_sum(data),
                    reference_sum(data),
                    "len={len}, offset={offset}"
                );
            }
        }
    }

    #[test]
    fn data_sum_preserves_carries_and_both_zero_representations() {
        for value in [0, 1, 0x7f, 0x80, 0xfe, 0xff] {
            let data = vec![value; 65535];
            for len in [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 65534, 65535] {
                assert_eq!(data_sum(&data[..len]), reference_sum(&data[..len]));
            }
        }
        assert_eq!(data_sum(&[0, 0]), 0);
        assert_eq!(data_sum(&[0xff, 0xff]), 0xffff);
    }

    #[test]
    fn tcp_checksum_can_be_zero_and_ignores_the_incoming_checksum() {
        let src = "10.0.0.2".parse().unwrap();
        let dst = "203.0.113.7".parse().unwrap();
        let mut data = [0; 20];
        let mut packet = TcpPacket::new_unchecked(&mut data[..]);
        packet.set_header_len(20);
        packet.fill_checksum(&src, &dst);
        // Adding the complement of the original sum makes the new sum 0xffff.
        packet.set_window_len(packet.checksum());
        packet.fill_checksum(&src, &dst);
        assert_eq!(packet.checksum(), 0);
        for incoming in [0, 1, 0x1234, 0xffff] {
            TcpPacket::new_unchecked(&mut data[..]).set_checksum(incoming);
            fill_tcp_checksum(&mut data, &src, &dst);
            let packet = TcpPacket::new_unchecked(&data[..]);
            assert_eq!(packet.checksum(), 0);
            assert!(packet.verify_checksum(&src, &dst));
        }
    }

    #[test]
    fn tcp_checksums_match_smoltcp_for_ipv4_ipv6_options_and_partial_input() {
        let mut rng = fastrand::Rng::with_seed(0xc5a1);
        let addresses: [(IpAddress, IpAddress); 4] = [
            ("10.0.0.2".parse().unwrap(), "203.0.113.7".parse().unwrap()),
            (
                "255.255.255.255".parse().unwrap(),
                "0.0.0.0".parse().unwrap(),
            ),
            (
                "2001:db8::1234".parse().unwrap(),
                "2001:db8::abcd".parse().unwrap(),
            ),
            (
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
                "::".parse().unwrap(),
            ),
        ];
        for (src, dst) in addresses {
            for header_len in [20, 24, 32, 60] {
                for payload_len in [0, 1, 2, 3, 31, 32, 33, 1460, 8960, 65415] {
                    let mut actual = vec![0; header_len + payload_len];
                    rng.fill(&mut actual);
                    // Random ports, flags, options, payload and incoming checksum.
                    TcpPacket::new_unchecked(&mut actual[..]).set_header_len(header_len as u8);
                    let mut expected = actual.clone();
                    TcpPacket::new_unchecked(&mut expected[..]).fill_checksum(&src, &dst);
                    fill_tcp_checksum(&mut actual, &src, &dst);
                    assert_eq!(actual, expected);
                    assert!(TcpPacket::new_unchecked(&actual[..]).verify_checksum(&src, &dst));
                }
            }
        }
    }
}
