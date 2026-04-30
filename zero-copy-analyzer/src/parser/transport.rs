//! Transport layer protocol parsing.
//!
//! This module provides zero-copy parsing of TCP, UDP, ICMP, and ICMPv6 headers.

use crate::parser::{ParseError, ParseResult};

/// Transport/Network layer protocol identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Internet Control Message Protocol
    Icmp,
    /// Internet Group Management Protocol
    Igmp,
    /// IPv4 encapsulation
    Ipv4,
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// IPv6
    Ipv6,
    /// IPv6 Routing Header
    Ipv6Route,
    /// IPv6 Fragment Header
    Ipv6Frag,
    /// Encapsulating Security Payload
    Esp,
    /// Authentication Header
    Ah,
    /// ICMP for IPv6
    Icmpv6,
    /// No Next Header (IPv6)
    NoNextHeader,
    /// Generic Routing Encapsulation
    Gre,
    /// Stream Control Transmission Protocol
    Sctp,
    /// Multipath TCP
    Mptcp,
    /// Fragmented packet
    Fragment,
    /// Address Resolution Protocol
    Arp,
    /// Link Layer Discovery Protocol
    Lldp,
    /// Unknown protocol
    Unknown,
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Icmp,
            2 => Protocol::Igmp,
            4 => Protocol::Ipv4,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            41 => Protocol::Ipv6,
            43 => Protocol::Ipv6Route,
            44 => Protocol::Ipv6Frag,
            50 => Protocol::Esp,
            51 => Protocol::Ah,
            58 => Protocol::Icmpv6,
            59 => Protocol::NoNextHeader,
            47 => Protocol::Gre,
            132 => Protocol::Sctp,
            262 => Protocol::Mptcp,
            _ => Protocol::Unknown,
        }
    }
}

impl From<Protocol> for u8 {
    fn from(protocol: Protocol) -> u8 {
        match protocol {
            Protocol::Icmp => 1,
            Protocol::Igmp => 2,
            Protocol::Ipv4 => 4,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Ipv6 => 41,
            Protocol::Ipv6Route => 43,
            Protocol::Ipv6Frag => 44,
            Protocol::Esp => 50,
            Protocol::Ah => 51,
            Protocol::Icmpv6 => 58,
            Protocol::NoNextHeader => 59,
            Protocol::Gre => 47,
            Protocol::Sctp => 132,
            Protocol::Mptcp => 262,
            _ => 0,
        }
    }
}

/// TCP header parsed from packet data
#[derive(Debug, Clone)]
pub struct TcpHeader<'a> {
    /// Raw header bytes (borrowed)
    pub raw: &'a [u8],
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Sequence number
    pub seq: u32,
    /// Acknowledgment number
    pub ack: u32,
    /// Data offset (header length / 4)
    pub data_offset: u8,
    /// Header length in bytes
    pub header_len: usize,
    /// FIN flag
    pub fin: bool,
    /// SYN flag
    pub syn: bool,
    /// RST flag
    pub rst: bool,
    /// PSH flag
    pub psh: bool,
    /// ACK flag
    pub ack_flag: bool,
    /// URG flag
    pub urg: bool,
    /// ECE flag
    pub ece: bool,
    /// CWR flag
    pub cwr: bool,
    /// NS flag
    pub ns: bool,
    /// Window size
    pub window: u16,
    /// Checksum
    pub checksum: u16,
    /// Urgent pointer
    pub urgent_ptr: u16,
    /// Options (if any)
    pub options: Option<&'a [u8]>,
}

impl<'a> TcpHeader<'a> {
    /// Get the acknowledgment flag (named differently to avoid conflict with ack field)
    pub fn is_ack(&self) -> bool {
        self.ack_flag
    }

    /// Check if this is a SYN packet (initial connection request)
    pub fn is_syn(&self) -> bool {
        self.syn && !self.ack_flag
    }

    /// Check if this is a SYN-ACK packet (connection acceptance)
    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack_flag
    }

    /// Check if this is a FIN packet (connection termination)
    pub fn is_fin(&self) -> bool {
        self.fin
    }

    /// Check if this is a RST packet (connection reset)
    pub fn is_rst(&self) -> bool {
        self.rst
    }

    /// Get TCP options as an iterator
    pub fn options_iter(&self) -> TcpOptionsIter<'a> {
        TcpOptionsIter::new(self.options.unwrap_or(&[]))
    }
}

/// TCP option types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOptionKind {
    /// End of options list
    End,
    /// No operation (padding)
    Nop,
    /// Maximum segment size
    Mss(u16),
    /// Window scale
    WindowScale(u8),
    /// Selective acknowledgment permitted
    SackPermitted,
    /// Selective acknowledgment
    Sack,
    /// Timestamp
    Timestamp { ts_val: u32, ts_ecr: u32 },
    /// Unknown option
    Unknown(u8),
}

/// Iterator over TCP options
pub struct TcpOptionsIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> TcpOptionsIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = TcpOptionKind;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let kind = self.data[self.offset];
        match kind {
            0 => {
                self.offset += 1;
                Some(TcpOptionKind::End)
            }
            1 => {
                self.offset += 1;
                Some(TcpOptionKind::Nop)
            }
            2 => {
                if self.offset + 4 > self.data.len() {
                    self.offset = self.data.len();
                    return None;
                }
                let mss = u16::from_be_bytes([
                    self.data[self.offset + 2],
                    self.data[self.offset + 3],
                ]);
                self.offset += 4;
                Some(TcpOptionKind::Mss(mss))
            }
            3 => {
                if self.offset + 3 > self.data.len() {
                    self.offset = self.data.len();
                    return None;
                }
                let scale = self.data[self.offset + 2];
                self.offset += 3;
                Some(TcpOptionKind::WindowScale(scale))
            }
            4 => {
                self.offset += 2;
                Some(TcpOptionKind::SackPermitted)
            }
            5 => {
                // SACK - variable length
                if self.offset + 2 > self.data.len() {
                    self.offset = self.data.len();
                    return None;
                }
                let len = self.data[self.offset + 1] as usize;
                if self.offset + len > self.data.len() {
                    self.offset = self.data.len();
                    return None;
                }
                self.offset += len;
                Some(TcpOptionKind::Sack)
            }
            8 => {
                if self.offset + 10 > self.data.len() {
                    self.offset = self.data.len();
                    return None;
                }
                let ts_val = u32::from_be_bytes([
                    self.data[self.offset + 2],
                    self.data[self.offset + 3],
                    self.data[self.offset + 4],
                    self.data[self.offset + 5],
                ]);
                let ts_ecr = u32::from_be_bytes([
                    self.data[self.offset + 6],
                    self.data[self.offset + 7],
                    self.data[self.offset + 8],
                    self.data[self.offset + 9],
                ]);
                self.offset += 10;
                Some(TcpOptionKind::Timestamp { ts_val, ts_ecr })
            }
            _ => {
                if self.offset + 2 > self.data.len() {
                    self.offset = self.data.len();
                    return None;
                }
                let len = self.data[self.offset + 1] as usize;
                if len < 2 {
                    self.offset = self.data.len();
                    return None;
                }
                if self.offset + len > self.data.len() {
                    self.offset = self.data.len();
                    return None;
                }
                self.offset += len;
                Some(TcpOptionKind::Unknown(kind))
            }
        }
    }
}

/// UDP header parsed from packet data
#[derive(Debug, Clone)]
pub struct UdpHeader<'a> {
    /// Raw header bytes (borrowed)
    pub raw: &'a [u8],
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Length (header + payload)
    pub length: u16,
    /// Checksum (0 means no checksum for IPv4)
    pub checksum: u16,
}

impl<'a> UdpHeader<'a> {
    const UDP_HEADER_LEN: usize = 8;

    /// Get payload length
    pub fn payload_len(&self) -> u16 {
        self.length.saturating_sub(Self::UDP_HEADER_LEN as u16)
    }
}

/// ICMP header parsed from packet data
#[derive(Debug, Clone)]
pub struct IcmpHeader<'a> {
    /// Raw header bytes (borrowed)
    pub raw: &'a [u8],
    /// ICMP type
    pub icmp_type: u8,
    /// ICMP code
    pub code: u8,
    /// Checksum
    pub checksum: u16,
    /// Rest of header (type-dependent)
    pub rest: &'a [u8],
}

impl<'a> IcmpHeader<'a> {
    const ICMP_HEADER_LEN: usize = 4;

    /// Get the identifier (for Echo Request/Reply)
    pub fn identifier(&self) -> Option<u16> {
        if self.rest.len() >= 2 {
            Some(u16::from_be_bytes([self.rest[0], self.rest[1]]))
        } else {
            None
        }
    }

    /// Get the sequence number (for Echo Request/Reply)
    pub fn sequence(&self) -> Option<u16> {
        if self.rest.len() >= 4 {
            Some(u16::from_be_bytes([self.rest[2], self.rest[3]]))
        } else {
            None
        }
    }

    /// Check if this is an Echo Request
    pub fn is_echo_request(&self) -> bool {
        self.icmp_type == 8
    }

    /// Check if this is an Echo Reply
    pub fn is_echo_reply(&self) -> bool {
        self.icmp_type == 0
    }

    /// Check if this is a Destination Unreachable
    pub fn is_dest_unreachable(&self) -> bool {
        self.icmp_type == 3
    }

    /// Check if this is a Time Exceeded
    pub fn is_time_exceeded(&self) -> bool {
        self.icmp_type == 11
    }
}

/// Parse a TCP header from raw data
///
/// # Arguments
///
/// * `data` - Raw packet data starting with TCP header
///
/// # Returns
///
/// Tuple of (TcpHeader, header_length)
///
/// # Examples
///
/// ```
/// use zero_copy_analyzer::parser::transport::parse_tcp;
///
/// let mut data = vec![0x00, 0x50, 0xc0, 0xa8, // Src: 80, Dst: 49320
///                     0x00, 0x00, 0x00, 0x00, // Seq
///                     0x00, 0x00, 0x00, 0x00, // Ack
///                     0x50, 0x02, 0xff, 0xff, // Offset/Flags, Window
///                     0x00, 0x00, 0x00, 0x00]; // Checksum, Urgent
/// let (header, len) = parse_tcp(&data).unwrap();
/// assert_eq!(header.src_port, 80);
/// assert_eq!(header.header_len, 20);
/// ```
pub fn parse_tcp(data: &[u8]) -> ParseResult<(TcpHeader<'_>, usize)> {
    const TCP_MIN_HEADER_LEN: usize = 20;

    if data.len() < TCP_MIN_HEADER_LEN {
        return Err(ParseError::TooShort {
            expected: TCP_MIN_HEADER_LEN,
            actual: data.len(),
        });
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
    let data_offset = ((data_offset_flags >> 12) & 0x0F) as u8;
    let header_len = (data_offset as usize) * 4;

    if header_len < TCP_MIN_HEADER_LEN || data.len() < header_len {
        return Err(ParseError::InvalidTcpHeader);
    }

    let flags = (data_offset_flags & 0x1FF) as u8;
    let fin = (flags & 0x01) != 0;
    let syn = (flags & 0x02) != 0;
    let rst = (flags & 0x04) != 0;
    let psh = (flags & 0x08) != 0;
    let ack_flag = (flags & 0x10) != 0;
    let urg = (flags & 0x20) != 0;
    let ece = (flags & 0x40) != 0;
    let cwr = (flags & 0x80) != 0;
    let ns = ((data[12] >> 7) & 0x01) != 0;

    let window = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

    let options = if header_len > TCP_MIN_HEADER_LEN {
        Some(&data[TCP_MIN_HEADER_LEN..header_len])
    } else {
        None
    };

    Ok((
        TcpHeader {
            raw: &data[..header_len],
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            header_len,
            fin,
            syn,
            rst,
            psh,
            ack_flag,
            urg,
            ece,
            cwr,
            ns,
            window,
            checksum,
            urgent_ptr,
            options,
        },
        header_len,
    ))
}

/// Parse a UDP header from raw data
///
/// # Arguments
///
/// * `data` - Raw packet data starting with UDP header
///
/// # Returns
///
/// Tuple of (UdpHeader, header_length)
///
/// # Examples
///
/// ```
/// use zero_copy_analyzer::parser::transport::parse_udp;
///
/// let data = [0x00, 0x35, 0xc0, 0xa8, // Src: 53, Dst: 49320
///             0x00, 0x08, 0x00, 0x00]; // Length, Checksum
/// let (header, len) = parse_udp(&data).unwrap();
/// assert_eq!(header.src_port, 53);
/// assert_eq!(len, 8);
/// ```
pub fn parse_udp(data: &[u8]) -> ParseResult<(UdpHeader<'_>, usize)> {
    const UDP_HEADER_LEN: usize = 8;

    if data.len() < UDP_HEADER_LEN {
        return Err(ParseError::TooShort {
            expected: UDP_HEADER_LEN,
            actual: data.len(),
        });
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);

    Ok((
        UdpHeader {
            raw: &data[..UDP_HEADER_LEN],
            src_port,
            dst_port,
            length,
            checksum,
        },
        UDP_HEADER_LEN,
    ))
}

/// Parse an ICMP header from raw data
///
/// # Arguments
///
/// * `data` - Raw packet data starting with ICMP header
///
/// # Returns
///
/// Tuple of (IcmpHeader, header_length)
pub fn parse_icmp(data: &[u8]) -> ParseResult<(IcmpHeader<'_>, usize)> {
    const ICMP_HEADER_LEN: usize = 4;

    if data.len() < ICMP_HEADER_LEN {
        return Err(ParseError::TooShort {
            expected: ICMP_HEADER_LEN,
            actual: data.len(),
        });
    }

    let icmp_type = data[0];
    let code = data[1];
    let checksum = u16::from_be_bytes([data[2], data[3]]);
    let rest = if data.len() > ICMP_HEADER_LEN {
        &data[ICMP_HEADER_LEN..]
    } else {
        &[]
    };

    Ok((
        IcmpHeader {
            raw: &data[..ICMP_HEADER_LEN.min(data.len())],
            icmp_type,
            code,
            checksum,
            rest,
        },
        ICMP_HEADER_LEN,
    ))
}

/// Parse an ICMPv6 header from raw data
///
/// Same structure as ICMP, just different type interpretation
pub fn parse_icmpv6(data: &[u8]) -> ParseResult<(IcmpHeader<'_>, usize)> {
    parse_icmp(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_basic() {
        let data = [
            0x00, 0x50, // Src: 80
            0xc0, 0xa8, // Dst: 49320
            0x00, 0x00, 0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x00, // Ack
            0x50, 0x02, // Offset=5 (20 bytes), Flags: SYN
            0xff, 0xff, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent
        ];

        let (header, len) = parse_tcp(&data).unwrap();
        assert_eq!(header.src_port, 80);
        assert_eq!(header.dst_port, 49320);
        assert_eq!(len, 20);
        assert!(header.syn);
        assert!(!header.ack_flag);
    }

    #[test]
    fn test_parse_udp_basic() {
        let data = [
            0x00, 0x35, // Src: 53 (DNS)
            0xc0, 0xa8, // Dst: 49320
            0x00, 0x0c, // Length: 12
            0x00, 0x00, // Checksum
        ];

        let (header, len) = parse_udp(&data).unwrap();
        assert_eq!(header.src_port, 53);
        assert_eq!(header.payload_len(), 4);
        assert_eq!(len, 8);
    }

    #[test]
    fn test_icmp_echo_request() {
        let data = [
            0x08, 0x00, // Type: 8 (Echo), Code: 0
            0x00, 0x00, // Checksum
            0x00, 0x01, // Identifier
            0x00, 0x01, // Sequence
        ];

        let (header, _) = parse_icmp(&data).unwrap();
        assert!(header.is_echo_request());
        assert_eq!(header.identifier(), Some(1));
        assert_eq!(header.sequence(), Some(1));
    }
}
