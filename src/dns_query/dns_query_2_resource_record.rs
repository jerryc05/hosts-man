#![allow(dead_code)]

use crate::dns_query::utils::{parse_var_name, parse_u16, parse_u32,
                              DnsQueryClass, DnsQueryType};
use crate::dns_query::utils::DnsQueryType::A;
use crate::dns_query::utils::DnsQueryClass::In;
use std::net::Ipv4Addr;
use std::mem::MaybeUninit;

//  Answer/Authority/Additional format
//
//    15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//     0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                     name                      |
//   /                                               /
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                     type                      |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                     class                     |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                                               |
//   |                      ttl                      |
//   |                                               |
//   |                                               |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                   rd_length                   |
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//   |                                               |
//   /                    r_data                     /
//   /                                               /
//   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug)]
pub(crate) struct DnsQueryResourceRecord {
  name: String,
  type_: DnsQueryType,
  class: DnsQueryClass,
  ttl: u32,
  rd_length: u16,
  r_data: Vec<u8>,
}

impl From<&[u8]> for DnsQueryResourceRecord {
  fn from(bytes: &[u8]) -> Self {
    #[allow(invalid_value)]
      let mut result = unsafe {
      Self {
        name: String::new(),
        type_: MaybeUninit::uninit().assume_init(),
        class: MaybeUninit::uninit().assume_init(),
        ttl: MaybeUninit::uninit().assume_init(),
        rd_length: MaybeUninit::uninit().assume_init(),
        r_data: MaybeUninit::uninit().assume_init(),
      }
    };
    let mut iter = bytes.iter();

    /* Parse name */ {
      parse_var_name(&mut iter, &mut result.name);
    }

    /* Parse type_ */ {
      result.type_ = parse_u16(&mut iter).into();
    }

    /* Parse class */ {
      result.class = parse_u16(&mut iter).into();
    }

    /* Parse ttl */ {
      result.ttl = parse_u32(&mut iter);
    }

    /* Parse rd_length */ {
      result.rd_length = parse_u16(&mut iter);
    }

    /* Parse r_data */ {
      result.r_data = iter.as_slice().to_vec();
    }

    result
  }
}

/* Type A -> Ipv4Addr */
impl DnsQueryResourceRecord {
  unsafe fn parse_ipv4addr_unchecked(&self) -> Ipv4Addr {
    Ipv4Addr::new(self.r_data[0], self.r_data[1], self.r_data[2], self.r_data[3])
  }
  fn parse_ipv4addr(&self) -> Result<Ipv4Addr, &str> {
    if let A = self.type_ {} else {
      return Err("Incorrect [type_] when parsing [Ipv4Addr]");
    }
    if self.r_data.len() != 4 {
      return Err("Incorrect [r_data] when parsing [Ipv4Addr]");
    }
    if let In = self.class {} else {
      return Err("Incorrect [class] when parsing [Ipv4Addr]");
    }
    Ok(unsafe { self.parse_ipv4addr_unchecked() })
  }
}