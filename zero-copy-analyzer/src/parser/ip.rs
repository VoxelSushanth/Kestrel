//! IP (Internet Protocol) header parsing.
//!
//! This module provides zero-copy parsing of IPv4 and IPv6 headers,
//! including IPv6 extension headers.

use std::net::Ipv4Addr;

use crate::parser::{IpAddr, ParseError, ParseResult, Protocol};

/// IP version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4
    V4,
    /// IPv6
    V6,
}

/// IPv4 header parsed from packet data
#[derive(Debug, Clone)]
pub struct Ipv4Header<'a> {
    /// Raw header bytes (borrowed)
    pub raw: &'a [u8],
    /// Header length in bytes (IHL * 4)
    pub header_len: usize,
    /// Total length (header + payload)
    pub total_len: u16,
    /// Identification field
    pub id: u16,
    /// Flags (3 bits)
    pub flags: u8,
    /// Fragment offset (13 bits)
    pub frag_offset: u16,
    /// Time to live
    pub ttl: u8,
    /// Protocol
    pub protocol: Protocol,
    /// Header checksum
    pub checksum: u16,
    /// Source address
    pub src_addr: Ipv4Addr,
    /// Destination address
    pub dst_addr: Ipv4Addr,
    /// Options (if any)
    pub options: Option<&'a [u8]>,
}

impl<'a> Ipv4Header<'a> {
    /// Get source address as IpAddr
    pub fn src_ip(&self) -> IpAddr {
        IpAddr::V4(self.src_addr)
    }

    /// Get destination address as IpAddr
    pub fn dst_ip(&self) -> IpAddr {
        IpAddr::V4(self.dst_addr)
    }

    /// Check if this is a fragment
    pub fn is_fragment(&self) -> bool {
        self.frag_offset != 0 || (self.flags & 0x01) != 0 // MF flag
    }

    /// Check if Don't Fragment flag is set
    pub fn dont_fragment(&self) -> bool {
        (self.flags & 0x02) != 0
    }

    /// Verify the header checksum
    pub fn verify_checksum(&self) -> bool {
        let mut sum: u32 = 0;
        for i in (0..self.header_len).step_by(2) {
            if i == 10 {
                // Skip checksum field
                continue;
            }
            let word = if i + 1 < self.header_len {
                u16::from_be_bytes([self.raw[i], self.raw[i + 1]]) as u32
            } else {
                (self.raw[i] as u32) << 8
            };
            sum += word;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum != 0 && sum != 0xFFFF
    }
}

/// IPv6 header parsed from packet data
#[derive(Debug, Clone)]
pub struct Ipv6Header<'a> {
    /// Raw header bytes (borrowed)
    pub raw: &'a [u8],
    /// Traffic class (8 bits)
    pub traffic_class: u8,
    /// Flow label (20 bits)
    pub flow_label: u32,
    /// Payload length
    pub payload_len: u16,
    /// Next header
    pub next_header: u8,
    /// Hop limit
    pub hop_limit: u8,
    /// Source address
    pub src_addr: [u8; 16],
    /// Destination address
    pub dst_addr: [u8; 16],
}

impl<'a> Ipv6Header<'a> {
    const IPV6_HEADER_LEN: usize = 40;

    /// Get source address as IpAddr
    pub fn src_ip(&self) -> IpAddr {
        IpAddr::V6(self.src_addr)
    }

    /// Get destination address as IpAddr
    pub fn dst_ip(&self) -> IpAddr {
        IpAddr::V6(self.dst_addr)
    }

    /// Check if this is a multicast address
    pub fn is_multicast(&self) -> bool {
        self.dst_addr[0] == 0xFF
    }
}

/// Parsed IP header (either IPv4 or IPv6)
#[derive(Debug, Clone)]
pub enum IpHeader<'a> {
    /// IPv4 header
    V4(Ipv4Header<'a>),
    /// IPv6 header
    V6(Ipv6Header<'a>),
}

impl<'a> IpHeader<'a> {
    /// Get the IP version
    pub fn version(&self) -> IpVersion {
        match self {
            IpHeader::V4(_) => IpVersion::V4,
            IpHeader::V6(_) => IpVersion::V6,
        }
    }

    /// Get source address
    pub fn src_addr(&self) -> IpAddr {
        match self {
            IpHeader::V4(v4) => v4.src_ip(),
            IpHeader::V6(v6) => v6.src_ip(),
        }
    }

    /// Get destination address
    pub fn dst_addr(&self) -> IpAddr {
        match self {
            IpHeader::V4(v4) => v4.dst_ip(),
            IpHeader::V6(v6) => v6.dst_ip(),
        }
    }

    /// Get the protocol/next header
    pub fn protocol(&self) -> u8 {
        match self {
            IpHeader::V4(v4) => v4.protocol as u8,
            IpHeader::V6(v6) => v6.next_header,
        }
    }

    /// Get header length
    pub fn header_len(&self) -> usize {
        match self {
            IpHeader::V4(v4) => v4.header_len,
            IpHeader::V6(_) => Ipv6Header::IPV6_HEADER_LEN,
        }
    }
}

/// Parse an IPv4 header from raw data
///
/// # Arguments
///
/// * `data` - Raw packet data starting with IPv4 header
///
/// # Returns
///
/// Tuple of (Ipv4Header, header_length)
///
/// # Examples
///
/// ```
/// use zero_copy_analyzer::parser::ip::parse_ipv4;
///
/// let mut data = vec![0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
///                     0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
///                     0x0a, 0x00, 0x00, 0x01];
/// let (header, len) = parse_ipv4(&data).unwrap();
/// assert_eq!(len, 20);
/// ```
pub fn parse_ipv4(data: &[u8]) -> ParseResult<(Ipv4Header<'_>, usize)> {
    const IPV4_MIN_HEADER_LEN: usize = 20;

    if data.len() < IPV4_MIN_HEADER_LEN {
        return Err(ParseError::TooShort {
            expected: IPV4_MIN_HEADER_LEN,
            actual: data.len(),
        });
    }

    let version = (data[0] >> 4) & 0x0F;
    if version != 4 {
        return Err(ParseError::InvalidIpVersion(version));
    }

    let ihl = data[0] & 0x0F;
    let header_len = (ihl as usize) * 4;

    if header_len < IPV4_MIN_HEADER_LEN {
        return Err(ParseError::InvalidIpHeaderLength(ihl));
    }

    if data.len() < header_len {
        return Err(ParseError::TooShort {
            expected: header_len,
            actual: data.len(),
        });
    }

    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let id = u16::from_be_bytes([data[4], data[5]]);

    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    let flags = ((flags_frag >> 13) & 0x07) as u8;
    let frag_offset = flags_frag & 0x1FFF;

    let ttl = data[8];
    let protocol_num = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);

    let src_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_addr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let options = if header_len > IPV4_MIN_HEADER_LEN {
        Some(&data[IPV4_MIN_HEADER_LEN..header_len])
    } else {
        None
    };

    let protocol = Protocol::from(protocol_num);

    Ok((
        Ipv4Header {
            raw: &data[..header_len],
            header_len,
            total_len,
            id,
            flags,
            frag_offset,
            ttl,
            protocol,
            checksum,
            src_addr,
            dst_addr,
            options,
        },
        header_len,
    ))
}

/// Parse an IPv6 header from raw data
///
/// # Arguments
///
/// * `data` - Raw packet data starting with IPv6 header
///
/// # Returns
///
/// Tuple of (Ipv6Header, header_length, next_header)
///
/// # Examples
///
/// ```
/// use zero_copy_analyzer::parser::ip::parse_ipv6;
///
/// let mut data = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x40,
///                     /* src addr */ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
///                     /* dst addr */ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
/// let (header, len, next) = parse_ipv6(&data).unwrap();
/// assert_eq!(len, 40);
/// ```
pub fn parse_ipv6(data: &[u8]) -> ParseResult<(Ipv6Header<'_>, usize, u8)> {
    const IPV6_HEADER_LEN: usize = 40;

    if data.len() < IPV6_HEADER_LEN {
        return Err(ParseError::TooShort {
            expected: IPV6_HEADER_LEN,
            actual: data.len(),
        });
    }

    let version_tc_flow = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let version = (version_tc_flow >> 28) & 0x0F;

    if version != 6 {
        return Err(ParseError::InvalidIpVersion(version as u8));
    }

    let traffic_class = ((version_tc_flow >> 20) & 0xFF) as u8;
    let flow_label = version_tc_flow & 0xFFFFF;

    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&data[8..24]);

    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(&data[24..40]);

    Ok((
        Ipv6Header {
            raw: &data[..IPV6_HEADER_LEN],
            traffic_class,
            flow_label,
            payload_len,
            next_header,
            hop_limit,
            src_addr,
            dst_addr,
        },
        IPV6_HEADER_LEN,
        next_header,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_basic() {
        let data = [
            0x45, 0x00, 0x00, 0x28, // Version/IHL, TOS, Total Length
            0x00, 0x00, // ID
            0x40, 0x00, // Flags/Frag Offset (DF set)
            0x40, // TTL
            0x06, // Protocol (TCP)
            0x00, 0x00, // Checksum
            0xc0, 0xa8, 0x01, 0x01, // Src: 192.168.1.1
            0x0a, 0x00, 0x00, 0x01, // Dst: 10.0.0.1
        ];

        let (header, len) = parse_ipv4(&data).unwrap();
        assert_eq!(len, 20);
        assert_eq!(header.version(), IpVersion::V4);
        assert_eq!(header.src_addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(header.dst_addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(header.protocol, Protocol::Tcp);
        assert!(header.dont_fragment());
    }

    #[test]
    fn test_parse_ipv4_with_options() {
        let mut data = vec![
            0x46, 0x00, 0x00, 0x28, // Version/IHL (6 = 24 bytes), TOS, Total Length
            0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            0xc0, 0xa8, 0x01, 0x01, 0x0a, 0x00, 0x00, 0x01,
            0x00, 0x00, // 4 bytes of options
        ];

        let (header, len) = parse_ipv4(&data).unwrap();
        assert_eq!(len, 24);
        assert!(header.options.is_some());
        assert_eq!(header.options.unwrap().len(), 4);
    }

    #[test]
    fn test_invalid_version() {
        let data = [0x50; 20]; // Version 5
        assert!(matches!(
            parse_ipv4(&data),
            Err(ParseError::InvalidIpVersion(5))
        ));
    }

    #[test]
    fn test_too_short_ipv4() {
        let data = [0x45; 15];
        assert!(matches!(
            parse_ipv4(&data),
            Err(ParseError::TooShort { .. })
        ));
    }
}
