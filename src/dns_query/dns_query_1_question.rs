use std::str::from_utf8_unchecked;
use DnsQueryQuestionTypeEnum::*;

//  Question format
//
//    15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//     0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                                               |
//   /                    q_name                     /
//   /                                               /
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                    q_type                     |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                    q_class                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Default)]
pub(crate) struct DnsQueryQuestion {
  q_name: String,
  q_type: DnsQueryQuestionType,
  q_class: u16,
}

impl From<&[u8]> for DnsQueryQuestion {
  fn from(bytes: &[u8]) -> Self {
    let mut result = DnsQueryQuestion::default();

    /* Parse q_name */
    let mut i = 0;
    {
      let max = bytes.len();
      while bytes[i] != 0 && i < max {
        let len = bytes[i] as usize;
        if !result.q_name.is_empty() {
          result.q_name.push('.');
        }
        result.q_name.push_str(
          unsafe { from_utf8_unchecked(&bytes[i + 1..=i + len]) });
        i += len + 1;
      }
    }

    /* Parse q_type  */ {
      i += 1; // advance from 0xff
      result.q_type.0 &= (bytes[i] as u16) << 0xf;
      i += 1;
      result.q_type.0 &= (bytes[i] as u16);
    }

    /* Parse q_class */ {
      i += 1; // advance from 0xff
      result.q_class &= (bytes[i] as u16) << 0xf;
      i += 1;
      result.q_class &= (bytes[i] as u16);
    }

    result
  }
}

#[derive(Debug, Default)]
pub(crate) struct DnsQueryQuestionType(u16);

impl From<DnsQueryQuestionTypeEnum> for DnsQueryQuestionType {
  fn from(enum_: DnsQueryQuestionTypeEnum) -> Self {
    DnsQueryQuestionType(enum_ as u16)
  }
}

pub(crate) enum DnsQueryQuestionTypeEnum {
  /// a host address
  A = 1,
  /// an authoritative name server
  Ns = 2,
  // /// a mail destination (OBSOLETE - use MX)
  // = 3,
  // /// a mail forwarder (OBSOLETE - use MX)
  // = 4,
  /// the canonical name for an alias
  CName = 5,
  /// marks the start of a zone of authority
  Soa = 6,
  /// a mailbox domain name (EXPERIMENTAL)
  Mb = 7,
  /// a mail group member (EXPERIMENTAL)
  Mg = 8,
  /// a mail rename domain name (EXPERIMENTAL)
  Mr = 9,
  /// a null RR (EXPERIMENTAL)
  Null = 10,
  /// a well known service description
  Wks = 11,
  /// a domain name pointer
  Ptr = 12,
  /// host information
  HInfo = 13,
  /// mailbox or mail list information
  MInfo = 14,
  /// mail exchange
  Mx = 15,
  /// text strings
  Txt = 16,
  /// for Responsible Person
  Rp = 17,
  /// for AFS Data Base location
  AfsDb = 18,
  /// for X.25 PSDN address
  X25 = 19,
  /// for ISDN address
  Isdn = 20,
  /// for Route Through
  Rt = 21,
  /// for NSAP address, NSAP style A record
  Nsap = 22,
  /// for domain name pointer, NSAP style
  NsapPtr = 23,
  /// for security signature
  Sig = 24,
  /// for security key
  Key = 25,
  /// X.400 mail mapping information
  Px = 26,
  /// Geographical Position
  GPos = 27,
  /// IP6 Address
  Aaaa = 28,
  /// Location Information
  Loc = 29,
  // /// Next Domain (OBSOLETE)
  // Nxt = 30,
  /// Endpoint Identifier
  EId = 31,
  /// Nimrod Locator
  NimLoc = 32,
  /// Server Selection
  Srv = 33,
  /// ATM Address
  AtmA = 34,
  /// Naming Authority Pointer
  NaPtr = 35,
  /// Key Exchanger
  Kx = 36,
  /// CERT
  Cert = 37,
  // /// A6 (OBSOLETE - use AAAA)
  // A6 = 38,
  /// DNAME
  DName = 39,
  /// SINK
  Sink = 40,
  /// OPT
  Opt = 41,
  /// APL
  Apl = 42,
  /// Delegation Signer
  Ds = 43,
  /// SSH Key Fingerprint
  SshFp = 44,
  /// IPSec Key
  IpSecKey = 45,
  /// DNSSEC signature
  RrSig = 46,
  /// Next Secure record
  NSec = 47,
  /// DNS Key record
  DnsKey = 48,
  /// DHCP identifier
  DhcId = 49,
  /// Next Secure record version 3
  NSec3 = 50,
  /// NSEC3 parameters
  NSec3Param = 51,
  /// TLSA certificate association
  Tlsa = 52,
  /// S/MIME cert association
  SMimeA = 53,
  /// Unassigned
  _UnAssign0 = 54,
  /// Host Identity Protocol
  Hip = 55,
  /// NINFO
  NInfo = 56,
  /// RKey
  RKey = 57,
  /// Trust Anchor LINK
  TaLink = 58,
  /// Child DS
  Cds = 59,
  /// DNSKEY(s) the Child wants reflected in DS
  CDnsKey = 60,
  /// OpenPGP public key record
  OpenPgpKey = 61,
  /// Child-to-Parent Synchronization
  CSync = 62,
  /// message digest for DNS zone
  ZoneMd = 63,
  /// 64-98: Unassigned
  _UnAssign1 = 98,  // use largest possible for correct `std::mem::transmute()` parsing
  /// Transaction Key record
  TKey = 249,
  /// Transaction Signature
  TSig = 250,
  /// Uniform Resource Identifier
  Uri = 256,
  /// Certification Authority Authorization
  Caa = 257,
  /// Application Visibility and Control
  Avc = 258,
  /// Digital Object Architecture
  DOa = 259,
  /// Automatic Multicast Tunneling Relay
  AmtRelay = 260,
  /// Unassigned
  _UnAssign2 = 32767,
  /// DNSSEC Trust Authorities
  Ta = 32768,
  /// DNSSEC Lookaside Validation record
  Dlv = 32769,
  /// 32770-65279: Unassigned
  _UnAssign3 = 65279,  // use largest possible for correct `std::mem::transmute()` parsing
  /// 65280-65534:	Private use
  _PrivUse = 65534,   // use largest possible for correct `std::mem::transmute()` parsing
  /// Reserved
  _Resv = 65535,
}

// impl From<DnsQueryQuestionType> for DnsQueryQuestionTypeEnum {
//   fn from(num: DnsQueryQuestionType) -> Self {
//     match num {} // todo
//   }
// }