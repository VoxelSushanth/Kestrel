//! Ethernet frame parsing.
//!
//! This module provides zero-copy parsing of Ethernet II frames,
//! including optional 802.1Q VLAN tags.

use crate::parser::{ParseError, ParseResult};

/// EtherType values for common protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    /// IPv4
    Ipv4,
    /// IPv6
    Ipv6,
    /// ARP
    Arp,
    /// Wake-on-LAN
    Wol,
    /// TRILL
    Trill,
    /// DECnet
    Decnet,
    /// RARP
    Rarp,
    /// AppleTalk
    Aarp,
    /// 802.1Q VLAN
    Vlan,
    /// PXE Boot
    Pxe,
    /// Link Layer Discovery Protocol
    Lldp,
    /// Precision Time Protocol
    Ptp,
    /// PPPoE Discovery
    PppoeDiscovery,
    /// PPPoE Session
    PppoeSession,
    /// MPLS unicast
    Mpls,
    /// MPLS multicast
    MplsMulticast,
    /// Unknown/custom EtherType
    Custom(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            0x0842 => EtherType::Wol,
            0x22F3 => EtherType::Trill,
            0x6003 => EtherType::Decnet,
            0x8035 => EtherType::Rarp,
            0x80F3 => EtherType::Aarp,
            0x8100 => EtherType::Vlan,
            0x86DD => EtherType::Ipv6,
            0x0800 => EtherType::Ipv4,
            0x88CC => EtherType::Lldp,
            0x88F7 => EtherType::Ptp,
            0x8863 => EtherType::PppoeDiscovery,
            0x8864 => EtherType::PppoeSession,
            0x8847 => EtherType::Mpls,
            0x8848 => EtherType::MplsMulticast,
            _ => EtherType::Custom(value),
        }
    }
}

impl From<EtherType> for u16 {
    fn from(ether_type: EtherType) -> u16 {
        match ether_type {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Arp => 0x0806,
            EtherType::Wol => 0x0842,
            EtherType::Trill => 0x22F3,
            EtherType::Decnet => 0x6003,
            EtherType::Rarp => 0x8035,
            EtherType::Aarp => 0x80F3,
            EtherType::Vlan => 0x8100,
            EtherType::Lldp => 0x88CC,
            EtherType::Ptp => 0x88F7,
            EtherType::PppoeDiscovery => 0x8863,
            EtherType::PppoeSession => 0x8864,
            EtherType::Mpls => 0x8847,
            EtherType::MplsMulticast => 0x8848,
            EtherType::Custom(v) => v,
        }
    }
}

/// Ethernet header parsed from a frame
#[derive(Debug, Clone)]
pub struct EthernetHeader<'a> {
    /// Destination MAC address (6 bytes)
    pub dst_mac: &'a [u8],
    /// Source MAC address (6 bytes)
    pub src_mac: &'a [u8],
    /// EtherType indicating payload protocol
    pub ether_type: EtherType,
}

impl<'a> EthernetHeader<'a> {
    /// Get destination MAC as array
    pub fn dst_mac_array(&self) -> [u8; 6] {
        [
            self.dst_mac[0],
            self.dst_mac[1],
            self.dst_mac[2],
            self.dst_mac[3],
            self.dst_mac[4],
            self.dst_mac[5],
        ]
    }

    /// Get source MAC as array
    pub fn src_mac_array(&self) -> [u8; 6] {
        [
            self.src_mac[0],
            self.src_mac[1],
            self.src_mac[2],
            self.src_mac[3],
            self.src_mac[4],
            self.src_mac[5],
        ]
    }

    /// Check if destination is broadcast
    pub fn is_broadcast(&self) -> bool {
        self.dst_mac.iter().all(|&b| b == 0xFF)
    }

    /// Check if destination is multicast
    pub fn is_multicast(&self) -> bool {
        self.dst_mac[0] & 0x01 != 0
    }
}

/// Parse an Ethernet header from raw data
///
/// Returns the parsed header and the offset to the payload (after any VLAN tags)
///
/// # Arguments
///
/// * `data` - Raw packet data starting with Ethernet header
///
/// # Returns
///
/// Tuple of (EthernetHeader, payload_offset)
///
/// # Examples
///
/// ```
/// use zero_copy_analyzer::parser::ethernet::parse_ethernet;
///
/// let data = vec![0u8; 14]; // Minimum Ethernet frame
/// let (header, offset) = parse_ethernet(&data).unwrap();
/// assert_eq!(offset, 14);
/// ```
pub fn parse_ethernet(data: &[u8]) -> ParseResult<(EthernetHeader<'_>, usize)> {
    const ETHERNET_HEADER_LEN: usize = 14;

    if data.len() < ETHERNET_HEADER_LEN {
        return Err(ParseError::TooShort {
            expected: ETHERNET_HEADER_LEN,
            actual: data.len(),
        });
    }

    let dst_mac = &data[0..6];
    let src_mac = &data[6..12];
    let ether_type = EtherType::from(u16::from_be_bytes([data[12], data[13]]));

    Ok((
        EthernetHeader {
            dst_mac,
            src_mac,
            ether_type,
        },
        ETHERNET_HEADER_LEN,
    ))
}

/// Parse a VLAN tag (802.1Q)
///
/// # Arguments
///
/// * `data` - Data starting at VLAN tag (4 bytes)
///
/// # Returns
///
/// Tuple of (priority, drop_eligible, vlan_id, next_ether_type)
pub fn parse_vlan_tag(data: &[u8]) -> ParseResult<(u8, bool, u16, EtherType)> {
    if data.len() < 4 {
        return Err(ParseError::TooShort {
            expected: 4,
            actual: data.len(),
        });
    }

    let tci = u16::from_be_bytes([data[0], data[1]]);
    let priority = ((tci >> 13) & 0x07) as u8;
    let drop_eligible = (tci >> 12) & 0x01 != 0;
    let vlan_id = tci & 0x0FFF;
    let ether_type = EtherType::from(u16::from_be_bytes([data[2], data[3]]));

    Ok((priority, drop_eligible, vlan_id, ether_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ethernet_ipv4() {
        let mut data = [0u8; 14];
        data[12] = 0x08;
        data[13] = 0x00;

        let (header, offset) = parse_ethernet(&data).unwrap();
        assert_eq!(offset, 14);
        assert_eq!(header.ether_type, EtherType::Ipv4);
    }

    #[test]
    fn test_parse_ethernet_ipv6() {
        let mut data = [0u8; 14];
        data[12] = 0x86;
        data[13] = 0xDD;

        let (header, _) = parse_ethernet(&data).unwrap();
        assert_eq!(header.ether_type, EtherType::Ipv6);
    }

    #[test]
    fn test_is_broadcast() {
        let data = [0xFFu8; 14];
        let (header, _) = parse_ethernet(&data).unwrap();
        assert!(header.is_broadcast());
    }

    #[test]
    fn test_is_multicast() {
        let mut data = [0u8; 14];
        data[0] = 0x01;
        let (header, _) = parse_ethernet(&data).unwrap();
        assert!(header.is_multicast());
    }

    #[test]
    fn test_too_short() {
        let data = [0u8; 10];
        assert!(parse_ethernet(&data).is_err());
    }
}
