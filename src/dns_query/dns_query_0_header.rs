use DnsQueryHeaderFlagsQr::*;
use DnsQueryHeaderFlagsOpcode::*;
use DnsQueryHeaderFlagsAa::*;
use DnsQueryHeaderFlagsTc::*;
use DnsQueryHeaderFlagsRd::*;
use DnsQueryHeaderFlagsRa::*;
use crate::dns_query::dns_query_0_header::DnsQueryHeaderFlagsRcode::{NoErr, FormatErr, SvrFailure, NameErr, NotImpl, Refused};

//  Header format
//
//    15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//     0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                      id                       |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |qr|  op_code  |aa|tc|rd|ra|   z    |  r_code   |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                   qd_count                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                   an_count                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                   ns_count                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                   ar_count                    |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug)]
pub(crate) struct DnsQueryHeader {
  pub(crate) id: u16,
  pub(crate) flags: DnsQueryHeaderFlags,
  pub(crate) qd_count: u16,
  pub(crate) an_count: u16,
  pub(crate) ns_count: u16,
  pub(crate) ar_count: u16,
}

//  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//   0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |qr|  op_code  |aa|tc|rd|ra|   z    |  r_code   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug)]
pub(crate) struct DnsQueryHeaderFlags(u16);

// qr
impl DnsQueryHeaderFlags {
  fn qr(&self) -> Result<DnsQueryHeaderFlagsQr, u8> {
    let val = ((self.0 >> 15) & 0b1) as u8;
    match val {
      0 => Ok(Query),
      1 => Ok(Response),
      _ => Err(val)
    }
  }
  fn qr_mut(&mut self, new: &DnsQueryHeaderFlagsQr) {
    let val: u16 = match new {
      Query => 0,
      Response => 1
    };
    self.0 &= val << 15;
  }
}

// op_code
impl DnsQueryHeaderFlags {
  fn op_code(&self) -> DnsQueryHeaderFlagsOpcode {
    let val = ((self.0 >> 11) & 0b1111) as u8;
    match val {
      0 => StdQuery,
      1 => InvQuery,
      2 => StatReq,
      _ => _Resv
    }
  }
  fn op_code_mut(&mut self, new: &DnsQueryHeaderFlagsOpcode) {
    let val: u16 = match new {
      StdQuery => 0,
      InvQuery => 1,
      StatReq => 2,
      _Resv => 3,
    };
    self.0 &= val << 11;
  }
}

// aa
impl DnsQueryHeaderFlags {
  fn aa(&self) -> DnsQueryHeaderFlagsAa {
    let val = ((self.0 >> 10) & 0b1) as u8;
    match val {
      0 => NonAuthAns,
      1 => AuthAns,
      _ => panic!("Invalid [aa] which shall not happen: [{}]!", val)
    }
  }
}

// tc
impl DnsQueryHeaderFlags {
  fn tc(&self) -> DnsQueryHeaderFlagsTc {
    let val = ((self.0 >> 9) & 0b1) as u8;
    match val {
      0 => NonTrunc,
      1 => Trunc,
      _ => panic!("Invalid [tc] which shall not happen: [{}]!", val)
    }
  }
  fn tc_mut(&mut self, new: &DnsQueryHeaderFlagsTc) {
    let val: u16 = match new {
      NonTrunc => 0,
      Trunc => 1
    };
    self.0 &= val << 9;
  }
}

// rd
impl DnsQueryHeaderFlags {
  fn rd(&self) -> DnsQueryHeaderFlagsRd {
    let val = ((self.0 >> 8) & 0b1) as u8;
    match val {
      0 => NotDesired,
      1 => Desired,
      _ => panic!("Invalid [rd] which shall not happen: [{}]!", val)
    }
  }
  fn rd_mut(&mut self, new: &DnsQueryHeaderFlagsRd) {
    let val: u16 = match new {
      NotDesired => 0,
      Desired => 1
    };
    self.0 &= val << 8;
  }
}

// ra
impl DnsQueryHeaderFlags {
  fn ra(&self) -> DnsQueryHeaderFlagsRa {
    let val = ((self.0 >> 7) & 0b1) as u8;
    match val {
      0 => NotAvailable,
      1 => Available,
      _ => panic!("Invalid [ra] which shall not happen: [{}]!", val)
    }
  }
  fn ra_mut(&mut self, new: &DnsQueryHeaderFlagsRa) {
    let val: u16 = match new {
      NotAvailable => 0,
      Available => 1
    };
    self.0 &= val << 7;
  }
}

// z

// r_code
impl DnsQueryHeaderFlags {
  fn r_code(&self) -> DnsQueryHeaderFlagsRcode {
    let val = (self.0 & 0b1111) as u8;
    match val {
      0 => NoErr,
      1 => FormatErr,
      2 => SvrFailure,
      3 => NameErr,
      4 => NotImpl,
      5 => Refused,
      _ => DnsQueryHeaderFlagsRcode::_Resv,
    }
  }
}


#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsQr {
  /// 0: a query (0)
  Query = 0,
  /// 1: a response (1)
  Response = 1,
}

#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsOpcode {
  /// 0: a standard query (QUERY)
  StdQuery = 0,
  /// 1: an inverse query (IQUERY)
  InvQuery = 1,
  /// 2: a server status request (STATUS)
  StatReq = 2,
  /// 3-15: reserved for future use
  _Resv = 3,
}

#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsAa {
  /// 0
  NonAuthAns = 0,
  /// 1
  AuthAns = 1,
}

#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsTc {
  /// 0
  NonTrunc = 0,
  /// 1
  Trunc = 1,
}

#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsRd {
  /// 0
  NotDesired = 0,
  /// 1
  Desired = 1,
}

#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsRa {
  /// 0
  NotAvailable = 0,
  /// 1
  Available = 1,
}

#[derive(Debug)]
pub(crate) enum DnsQueryHeaderFlagsRcode {
  /// 0: No error condition
  NoErr = 0,
  /// 1: Format error - The name server was unable to interpret the query.
  FormatErr = 1,
  /// 2: Server failure - The name server was unable to process this query
  ///                     due to a problem with the name server.
  SvrFailure = 2,
  /// 3: Name Error - Meaningful only for responses from an authoritative
  ///                 name server, this code signifies that the domain name
  ///                 referenced in the query does not exist.
  NameErr = 3,
  /// 4: Not Implemented - The name server does not support the requested
  ///                      kind of query.
  NotImpl = 4,
  /// 5: Refused - The name server refuses to perform the specified operation
  ///              for policy reasons.  For example, a name server may not
  ///              wish to provide the information to the particular requester,
  ///              or a name server may not wish to perform a particular
  ///              operation (e.g., zone transfer) for particular data.
  Refused = 5,
  /// 6-15: Reserved for future use.
  _Resv = 6,
}