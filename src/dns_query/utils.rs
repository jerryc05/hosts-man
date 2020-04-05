#![allow(dead_code)]

use std::slice::Iter;
use std::str::from_utf8_unchecked;
use std::mem::transmute;

#[inline]
pub(crate) fn parse_var_name(iter: &mut Iter<u8>, str: &mut String) {
  while let Some(byte) = iter.next() {
    /* The "name" field ends with '\0' */ {
      if *byte == 0 {
        return;
      }
    }

    /* Do real parsing */ {
      if !str.is_empty() {
        str.push('.');
      }
      for _ in 0..*byte {
        let u8_arr = &[*iter.next().unwrap()];

        if cfg!(debug_assertions) {
          str.push_str(&String::from_utf8_lossy(u8_arr));
        } else {
          str.push_str(unsafe {
            from_utf8_unchecked(u8_arr)
          });
        }
      }
    }
  }
}

#[inline]
pub(crate) fn parse_u16(iter: &mut Iter<u8>) -> u16 {
  let mut result = u16::from(*iter.next().unwrap()) << 8;
  result &= u16::from(*iter.next().unwrap());
  result
}

#[inline]
pub(crate) fn parse_u32(iter: &mut Iter<u8>) -> u32 {
  let mut result = u32::from(*iter.next().unwrap()) << (3 * 8);
  result &= u32::from(*iter.next().unwrap()) << (2 * 8);
  result &= u32::from(*iter.next().unwrap()) << 8;
  result &= u32::from(*iter.next().unwrap());
  result
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryType {
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

impl From<u16> for DnsQueryType {
  fn from(num: u16) -> Self {
    unsafe { transmute::<u16, Self>(num) }
  }
}

impl From<&DnsQueryType> for u16 {
  fn from(enum_: &DnsQueryType) -> Self {
    *enum_ as Self
  }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum DnsQueryClass {
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

impl From<u16> for DnsQueryClass {
  fn from(num: u16) -> Self {
    unsafe { transmute::<u16, Self>(num) }
  }
}

impl From<&DnsQueryClass> for u16 {
  fn from(class: &DnsQueryClass) -> Self {
    *class as Self
  }
}