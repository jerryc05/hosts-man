#![allow(dead_code)]

use crate::dns_query::utils::{parse_var_name, parse_u16,
                              DnsQueryType, DnsQueryClass};
use std::mem::MaybeUninit;

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
  pub(crate) q_type: DnsQueryType,
  pub(crate) q_class: DnsQueryClass,
}

impl From<&[u8]> for DnsQueryQuestion {
  fn from(bytes: &[u8]) -> Self {
    let mut result = unsafe {
      Self {
        q_name: String::new(),
        q_type: MaybeUninit::uninit().assume_init(),
        q_class: MaybeUninit::uninit().assume_init(),
      }
    };
    let mut iter = bytes.iter();

    /* Parse q_name */
    parse_var_name(&mut iter, &mut result.q_name);

    /* Parse q_type  */ {
      result.q_type = parse_u16(&mut iter).into();
    }

    /* Parse q_class */ {
      result.q_class = parse_u16(&mut iter).into();
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