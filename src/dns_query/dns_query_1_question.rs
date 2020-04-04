#![allow(dead_code)]

use std::str::from_utf8_unchecked;
use std::mem::transmute;
use DnsQueryQuestionClass::In;
use DnsQueryQuestionType::A;

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
#[derive(Debug)]
pub(crate) struct DnsQueryQuestion {
  pub(crate) q_name: String,
  pub(crate) q_type: DnsQueryQuestionType,
  pub(crate) q_class: DnsQueryQuestionClass,
}

impl From<&[u8]> for DnsQueryQuestion {
  fn from(bytes: &[u8]) -> Self {
    let mut result = DnsQueryQuestion {
      q_name: String::new(),
      q_type: A,
      q_class: In,
    };

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
      let mut q_type = 0_u16;
      i += 1; // advance from 0xff
      q_type &= (bytes[i] as u16) << 0xf;
      i += 1;
      q_type &= bytes[i] as u16;
      result.q_type = q_type.into();
    }

    /* Parse q_class */ {
      let mut q_class = 0_u16;
      i += 1; // advance from 0xff
      q_class &= (bytes[i] as u16) << 0xf;
      i += 1;
      q_class &= bytes[i] as u16;
      result.q_class = q_class.into();
    }

    result
  }
}

impl From<DnsQueryQuestion> for Vec<u8> {
  fn from(question: DnsQueryQuestion) -> Self {
    let mut result = vec![];

    /* Parse q_name */ {
      for word in question.q_name.split('.') {
        let len = word.len();
        result.push(len as u8);
        for i in 0..len {
          result.push(word.as_bytes()[i]);
        }
      }
    }

    /* Parse q_type */ {
      let q_type: u16 = (&question.q_class).into();
      result.push((q_type >> 8) as u8);
      result.push((q_type & 0xff) as u8);
    }

    /* Parse q_class */ {
      let q_class: u16 = (&question.q_class).into();
      result.push((q_class >> 8) as u8);
      result.push((q_class & 0xff) as u8);
    }

    result
  }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryQuestionType {
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
  _UnAssign54 = 54,
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
  // use largest possible for correct `std::mem::transmute()` parsing
  _UnAssign64To98 = 98,
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
  _UnAssign32767 = 32767,
  /// DNSSEC Trust Authorities
  Ta = 32768,
  /// DNSSEC Lookaside Validation record
  Dlv = 32769,
  /// 32770-65279: Unassigned
  // use largest possible for correct `std::mem::transmute()` parsing
  _UnAssign32770To65279 = 65279,
  /// 65280-65534: Private use
  // use largest possible for correct `std::mem::transmute()` parsing
  _PrivUse = 65534,
  /// Reserved
  _Resv65535 = 65535,
}

impl From<u16> for DnsQueryQuestionType {
  fn from(num: u16) -> Self {
    unsafe { transmute::<u16, Self>(num) }
  }
}

impl From<&DnsQueryQuestionType> for u16 {
  fn from(enum_: &DnsQueryQuestionType) -> Self {
    *enum_ as Self
  }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryQuestionClass {
  /// 0: Reserved
  _Resv0 = 0,
  /// 1: Internet (IN)
  In = 1,
  /// 2: Unassigned
  _UnAssign2 = 2,
  /// 3: Chaos (CH)
  Ch = 3,
  /// 4: Hesiod (HS)
  Hs = 4,
  /// 5-253: Unassigned
  // use largest possible for correct `std::mem::transmute()` parsing
  _UnAssign5To253 = 253,
  /// 254: QCLASS NONE
  QClsNone = 254,
  /// 255: QCLASS * (ANY)
  QClsAny = 255,
  /// 256-65279: Unassigned
  // use largest possible for correct `std::mem::transmute()` parsing
  _UnAssign256To65279 = 65279,
  /// 65280-65534: Reserved for Private Use
  // use largest possible for correct `std::mem::transmute()` parsing
  _Priv65280To65534 = 65534,
  /// 65535: Reserved
  _Resv65535 = 65535,
}

impl From<u16> for DnsQueryQuestionClass {
  fn from(num: u16) -> Self {
    unsafe { transmute::<u16, Self>(num) }
  }
}

impl From<&DnsQueryQuestionClass> for u16 {
  fn from(class: &DnsQueryQuestionClass) -> Self {
    *class as Self
  }
}