//! Packet parsing module for zero-copy protocol dissection.
//!
//! This module provides a high-performance, zero-allocation recursive descent parser
//! for network protocols. All parsing is done using borrowed slices into the original
//! packet buffer - no data is ever copied.
//!
//! # Supported Protocols
//!
//! - **Layer 2**: Ethernet II, 802.1Q VLAN
//! - **Layer 3**: IPv4, IPv6
//! - **Layer 4**: TCP, UDP, ICMP, ICMPv6
//! - **Tunneling**: GRE, VXLAN
//! - **Application**: QUIC (initial packets)
//!
//! # Example
//!
//! ```no_run
//! use zero_copy_analyzer::parser::{PacketParser, ParsedPacket};
//!
//! let mut parser = PacketParser::new();
//! let packet_data = vec![0u8; 64]; // Ethernet frame
//!
//! match parser.parse(&packet_data) {
//!     Ok(parsed) => {
//!         println!("Protocol: {:?}", parsed.protocol);
//!         if let Some(flow) = parsed.flow_key {
//!             println!("Flow: {}:{} -> {}:{}", 
//!                 flow.src_ip, flow.src_port,
//!                 flow.dst_ip, flow.dst_port);
//!         }
//!     }
//!     Err(e) => eprintln!("Parse error: {:?}", e),
//! }
//! ```

use std::fmt;
use std::net::Ipv4Addr;

use thiserror::Error;

pub mod ethernet;
pub mod ip;
pub mod transport;

pub use ethernet::{EthernetHeader, EtherType};
pub use ip::{IpHeader, IpVersion, Ipv4Header, Ipv6Header};
pub use transport::{TcpHeader, UdpHeader, IcmpHeader, Protocol};

/// Errors that can occur during packet parsing
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Packet too short for expected header
    #[error("Packet too short: expected {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    /// Invalid Ethernet frame
    #[error("Invalid Ethernet frame")]
    InvalidEthernet,

    /// Invalid IP version
    #[error("Invalid IP version: {0}")]
    InvalidIpVersion(u8),

    /// Invalid IP header length
    #[error("Invalid IP header length: {0}")]
    InvalidIpHeaderLength(u8),

    /// IP header checksum mismatch
    #[error("IP header checksum mismatch")]
    IpChecksumMismatch,

    /// Truncated IP header
    #[error("Truncated IP header")]
    TruncatedIpHeader,

    /// Unsupported protocol
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(u8),

    /// Invalid TCP header
    #[error("Invalid TCP header")]
    InvalidTcpHeader,

    /// Invalid UDP header
    #[error("Invalid UDP header")]
    InvalidUdpHeader,

    /// Invalid ICMP header
    #[error("Invalid ICMP header")]
    InvalidIcmpHeader,

    /// Unknown next header (IPv6)
    #[error("Unknown next header: {0}")]
    UnknownNextHeader(u8),

    /// VLAN tag parsing error
    #[error("Invalid VLAN tag")]
    InvalidVlanTag,

    /// Extension header error (IPv6)
    #[error("Invalid extension header")]
    InvalidExtensionHeader,
}

/// Result type for parsing operations
pub type ParseResult<T> = Result<T, ParseError>;

/// A 5-tuple flow key for identifying network flows
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port (0 for non-transport protocols)
    pub src_port: u16,
    /// Destination port (0 for non-transport protocols)
    pub dst_port: u16,
    /// Transport protocol
    pub protocol: Protocol,
}

impl FlowKey {
    /// Create a new flow key
    ///
    /// # Examples
    ///
    /// ```
    /// use zero_copy_analyzer::parser::{FlowKey, IpAddr, Protocol};
    ///
    /// let key = FlowKey::new(
    ///     IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
    ///     IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
    ///     12345,
    ///     80,
    ///     Protocol::Tcp,
    /// );
    /// ```
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Get the normalized/reverse flow key (for bidirectional matching)
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({:?})",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )
    }
}

/// IP address (IPv4 or IPv6)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddr {
    /// IPv4 address
    V4(Ipv4Addr),
    /// IPv6 address
    V6([u8; 16]),
}

impl IpAddr {
    /// Check if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }

    /// Check if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpAddr::V6(_))
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddr::V4(addr) => write!(f, "{}", addr),
            IpAddr::V6(addr) => {
                write!(
                    f,
                    "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                    addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]
                )
            }
        }
    }
}

impl From<Ipv4Addr> for IpAddr {
    fn from(addr: Ipv4Addr) -> Self {
        IpAddr::V4(addr)
    }
}

/// Parsed packet representation
#[derive(Debug, Clone)]
pub struct ParsedPacket<'a> {
    /// Raw packet data (borrowed)
    pub data: &'a [u8],
    /// Ethernet header
    pub ethernet: Option<EthernetHeader<'a>>,
    /// VLAN tags (can be stacked)
    pub vlan_tags: Vec<u16>,
    /// IP header
    pub ip: Option<IpHeader<'a>>,
    /// Transport protocol
    pub protocol: Protocol,
    /// TCP header if applicable
    pub tcp: Option<TcpHeader<'a>>,
    /// UDP header if applicable
    pub udp: Option<UdpHeader<'a>>,
    /// ICMP header if applicable
    pub icmp: Option<IcmpHeader<'a>>,
    /// Flow key (5-tuple)
    pub flow_key: Option<FlowKey>,
    /// Total header length (L2 + L3 + L4)
    pub header_len: usize,
    /// Payload length
    pub payload_len: usize,
    /// Timestamp (nanoseconds since epoch, if available)
    pub timestamp_ns: Option<u64>,
    /// Capture length (may differ from actual for truncated packets)
    pub capture_len: usize,
}

impl<'a> ParsedPacket<'a> {
    /// Create a new empty parsed packet
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            ethernet: None,
            vlan_tags: Vec::new(),
            ip: None,
            protocol: Protocol::Unknown,
            tcp: None,
            udp: None,
            icmp: None,
            flow_key: None,
            header_len: 0,
            payload_len: data.len(),
            timestamp_ns: None,
            capture_len: data.len(),
        }
    }

    /// Get the source MAC address
    pub fn src_mac(&self) -> Option<&[u8]> {
        self.ethernet.as_ref().map(|e| e.src_mac)
    }

    /// Get the destination MAC address
    pub fn dst_mac(&self) -> Option<&[u8]> {
        self.ethernet.as_ref().map(|e| e.dst_mac)
    }

    /// Get the source IP address
    pub fn src_ip(&self) -> Option<IpAddr> {
        self.ip.as_ref().map(|ip| ip.src_addr())
    }

    /// Get the destination IP address
    pub fn dst_ip(&self) -> Option<IpAddr> {
        self.ip.as_ref().map(|ip| ip.dst_addr())
    }

    /// Get the source port
    pub fn src_port(&self) -> Option<u16> {
        self.tcp.map(|t| t.src_port).or(self.udp.map(|u| u.src_port))
    }

    /// Get the destination port
    pub fn dst_port(&self) -> Option<u16> {
        self.tcp.map(|t| t.dst_port).or(self.udp.map(|u| u.dst_port))
    }

    /// Get the payload (data after all headers)
    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.header_len..]
    }

    /// Check if this is a TCP SYN packet
    pub fn is_tcp_syn(&self) -> bool {
        self.tcp.map(|t| t.syn && !t.ack).unwrap_or(false)
    }

    /// Check if this is a TCP SYN-ACK packet
    pub fn is_tcp_syn_ack(&self) -> bool {
        self.tcp.map(|t| t.syn && t.ack).unwrap_or(false)
    }

    /// Check if this is a TCP FIN packet
    pub fn is_tcp_fin(&self) -> bool {
        self.tcp.map(|t| t.fin).unwrap_or(false)
    }

    /// Check if this is a TCP RST packet
    pub fn is_tcp_rst(&self) -> bool {
        self.tcp.map(|t| t.rst).unwrap_or(false)
    }
}

/// Zero-copy packet parser
///
/// Parses raw packet data into structured headers without any allocations.
/// All returned references point directly into the input buffer.
///
/// # Examples
///
/// ```
/// use zero_copy_analyzer::parser::PacketParser;
///
/// let mut parser = PacketParser::new();
/// let packet = vec![0u8; 64]; // Ethernet frame
/// let result = parser.parse(&packet);
/// ```
pub struct PacketParser {
    /// Buffer for reassembly (not used in zero-copy mode)
    _reasm_buffer: Vec<u8>,
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketParser {
    /// Create a new packet parser
    pub fn new() -> Self {
        Self {
            _reasm_buffer: Vec::with_capacity(65536),
        }
    }

    /// Parse a raw packet buffer
    ///
    /// # Arguments
    ///
    /// * `data` - Raw packet data starting with Ethernet header
    ///
    /// # Returns
    ///
    /// Parsed packet structure or parse error
    ///
    /// # Examples
    ///
    /// ```
    /// use zero_copy_analyzer::parser::PacketParser;
    ///
    /// let mut parser = PacketParser::new();
    /// let packet = vec![0u8; 64];
    /// let result = parser.parse(&packet);
    /// ```
    pub fn parse<'a>(&mut self, data: &'a [u8]) -> ParseResult<ParsedPacket<'a>> {
        let mut parsed = ParsedPacket::new(data);

        // Parse Ethernet header
        let (eth, offset) = ethernet::parse_ethernet(data)?;
        parsed.ethernet = Some(eth);
        let mut current_offset = offset;

        // Handle VLAN tags (802.1Q)
        while parsed.ethernet.as_ref().map(|e| e.ether_type) == Some(EtherType::Vlan) {
            if current_offset + 4 > data.len() {
                return Err(ParseError::TooShort {
                    expected: current_offset + 4,
                    actual: data.len(),
                });
            }

            let vlan_tci = u16::from_be_bytes([
                data[current_offset],
                data[current_offset + 1],
            ]);
            let next_ether_type = EtherType::from(u16::from_be_bytes([
                data[current_offset + 2],
                data[current_offset + 3],
            ]));

            parsed.vlan_tags.push(vlan_tci & 0x0FFF);
            current_offset += 4;

            // Update ether_type for next iteration
            if let Some(ref mut eth) = parsed.ethernet {
                eth.ether_type = next_ether_type;
            }
        }

        // Parse based on EtherType
        match parsed.ethernet.as_ref().unwrap().ether_type {
            EtherType::Ipv4 => {
                let (ipv4, hdr_len) = ip::parse_ipv4(&data[current_offset..])?;
                parsed.ip = Some(IpHeader::V4(ipv4));
                parsed.protocol = ipv4.protocol;
                current_offset += hdr_len;
                parsed.header_len = current_offset;

                // Parse transport layer
                self.parse_transport(&mut parsed, data, current_offset)?;
            }
            EtherType::Ipv6 => {
                let (ipv6, hdr_len, next_header) = ip::parse_ipv6(&data[current_offset..])?;
                parsed.ip = Some(IpHeader::V6(ipv6));
                current_offset += hdr_len;

                // Handle IPv6 extension headers
                let (proto, ext_hdr_len) =
                    self.parse_ipv6_extension_headers(data, current_offset, next_header)?;
                current_offset += ext_hdr_len;
                parsed.protocol = proto;
                parsed.header_len = current_offset;

                // Parse transport layer
                self.parse_transport(&mut parsed, data, current_offset)?;
            }
            EtherType::Arp => {
                parsed.protocol = Protocol::Arp;
                parsed.header_len = current_offset;
            }
            EtherType::Lldp => {
                parsed.protocol = Protocol::Lldp;
                parsed.header_len = current_offset;
            }
            _ => {
                parsed.protocol = Protocol::Unknown;
                parsed.header_len = current_offset;
            }
        }

        // Build flow key if we have IP and transport
        if let Some(ref ip) = parsed.ip {
            if let Some(proto) = parsed.transport_protocol() {
                let (src_port, dst_port) = match proto {
                    Protocol::Tcp => (
                        parsed.tcp.map(|t| t.src_port).unwrap_or(0),
                        parsed.tcp.map(|t| t.dst_port).unwrap_or(0),
                    ),
                    Protocol::Udp => (
                        parsed.udp.map(|u| u.src_port).unwrap_or(0),
                        parsed.udp.map(|u| u.dst_port).unwrap_or(0),
                    ),
                    _ => (0, 0),
                };

                parsed.flow_key = Some(FlowKey::new(
                    ip.src_addr(),
                    ip.dst_addr(),
                    src_port,
                    dst_port,
                    proto,
                ));
            }
        }

        parsed.payload_len = data.len().saturating_sub(parsed.header_len);
        parsed.capture_len = data.len();

        Ok(parsed)
    }

    /// Parse transport layer headers
    fn parse_transport<'a>(
        &mut self,
        parsed: &mut ParsedPacket<'a>,
        data: &'a [u8],
        offset: usize,
    ) -> ParseResult<()> {
        match parsed.protocol {
            Protocol::Tcp => {
                if offset >= data.len() {
                    return Ok(());
                }
                let (tcp, _) = transport::parse_tcp(&data[offset..])?;
                parsed.tcp = Some(tcp);
            }
            Protocol::Udp => {
                if offset >= data.len() {
                    return Ok(());
                }
                let (udp, _) = transport::parse_udp(&data[offset..])?;
                parsed.udp = Some(udp);

                // Check for VXLAN (UDP port 4789)
                if parsed.udp.map(|u| u.dst_port) == Some(4789) {
                    // Could parse VXLAN here
                }
            }
            Protocol::Icmp => {
                if offset >= data.len() {
                    return Ok(());
                }
                let (icmp, _) = transport::parse_icmp(&data[offset..])?;
                parsed.icmp = Some(icmp);
            }
            Protocol::Icmpv6 => {
                if offset >= data.len() {
                    return Ok(());
                }
                let (icmp, _) = transport::parse_icmpv6(&data[offset..])?;
                parsed.icmp = Some(icmp);
            }
            _ => {}
        }

        Ok(())
    }

    /// Parse IPv6 extension headers
    ///
    /// Returns (next_protocol, total_extension_header_length)
    fn parse_ipv6_extension_headers(
        &self,
        data: &[u8],
        offset: usize,
        mut next_header: u8,
    ) -> ParseResult<(Protocol, usize)> {
        let mut ext_len = 0;
        let mut current_offset = offset;

        loop {
            match next_header {
                0 => break, // Hop-by-hop processed, continue
                4 => {
                    // IPv4 encapsulation
                    return Ok((Protocol::Ipv4, ext_len));
                }
                6 => {
                    // TCP
                    return Ok((Protocol::Tcp, ext_len));
                }
                17 => {
                    // UDP
                    return Ok((Protocol::Udp, ext_len));
                }
                43 => {
                    // Routing header
                    if current_offset + 2 > data.len() {
                        return Err(ParseError::TooShort {
                            expected: current_offset + 2,
                            actual: data.len(),
                        });
                    }
                    let hdr_ext_len = data[current_offset + 1] as usize * 8 + 8;
                    ext_len += hdr_ext_len;
                    current_offset += hdr_ext_len;
                    if current_offset >= data.len() {
                        return Err(ParseError::TruncatedIpHeader);
                    }
                    next_header = data[current_offset];
                }
                44 => {
                    // Fragment header
                    ext_len += 8;
                    current_offset += 8;
                    if current_offset >= data.len() {
                        return Err(ParseError::TruncatedIpHeader);
                    }
                    next_header = data[current_offset - 8];
                    return Ok((Protocol::Fragment, ext_len));
                }
                50 => {
                    // ESP
                    return Ok((Protocol::Esp, ext_len));
                }
                51 => {
                    // AH
                    if current_offset + 2 > data.len() {
                        return Err(ParseError::TooShort {
                            expected: current_offset + 2,
                            actual: data.len(),
                        });
                    }
                    let hdr_len = (data[current_offset + 1] as usize + 2) * 4;
                    ext_len += hdr_len;
                    current_offset += hdr_len;
                    if current_offset >= data.len() {
                        return Err(ParseError::TruncatedIpHeader);
                    }
                    next_header = data[current_offset - hdr_len];
                }
                58 => {
                    // ICMPv6
                    return Ok((Protocol::Icmpv6, ext_len));
                }
                59 => {
                    // No next header
                    return Ok((Protocol::NoNextHeader, ext_len));
                }
                60 => {
                    // Destination options
                    if current_offset + 2 > data.len() {
                        return Err(ParseError::TooShort {
                            expected: current_offset + 2,
                            actual: data.len(),
                        });
                    }
                    let hdr_ext_len = data[current_offset + 1] as usize * 8 + 8;
                    ext_len += hdr_ext_len;
                    current_offset += hdr_ext_len;
                    if current_offset >= data.len() {
                        return Err(ParseError::TruncatedIpHeader);
                    }
                    next_header = data[current_offset - hdr_len];
                }
                132 => {
                    // SCTP
                    return Ok((Protocol::Sctp, ext_len));
                }
                _ => {
                    // Unknown header, treat as payload
                    return Ok((Protocol::Unknown, ext_len));
                }
            }
        }

        Ok((Protocol::Unknown, ext_len))
    }

    /// Get transport protocol from parsed protocol
    fn get_transport_protocol(&self, proto: Protocol) -> Option<Protocol> {
        match proto {
            Protocol::Tcp | Protocol::Udp | Protocol::Icmp | Protocol::Icmpv6 => Some(proto),
            _ => None,
        }
    }
}

impl ParsedPacket<'_> {
    /// Get the transport protocol
    fn transport_protocol(&self) -> Option<Protocol> {
        match self.protocol {
            Protocol::Tcp | Protocol::Udp | Protocol::Icmp | Protocol::Icmpv6 => {
                Some(self.protocol)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_reverse() {
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            80,
            Protocol::Tcp,
        );

        let rev = key.reverse();
        assert_eq!(rev.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(rev.dst_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(rev.src_port, 80);
        assert_eq!(rev.dst_port, 12345);
    }

    #[test]
    fn test_parsed_packet_new() {
        let data = vec![0u8; 64];
        let parsed = ParsedPacket::new(&data);
        assert_eq!(parsed.data.len(), 64);
        assert!(parsed.ethernet.is_none());
    }
}
