#![allow(dead_code)]

use crate::dns_query::utils::{iter_to_str, iter_to_u16_be,
                              DnsQueryType, DnsQueryClass};
use std::convert::TryFrom;
use std::num::TryFromIntError;
use std::option::NoneError;

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

impl TryFrom<&[u8]> for DnsQueryQuestion {
  type Error = NoneError;

  fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
    let mut iter = bytes.iter();

    /* Parse q_name */
    let mut q_name;
    {
      q_name = String::new();
      iter_to_str(&mut iter, &mut q_name);
    }

    /* Parse q_type  */
    let q_type = iter_to_u16_be(&mut iter)?.into();

    /* Parse q_class */
    let q_class = iter_to_u16_be(&mut iter)?.into();

    Ok(Self { q_name, q_type, q_class })
  }
}

impl TryFrom<DnsQueryQuestion> for Vec<u8> {
  type Error = TryFromIntError;

  fn try_from(question: DnsQueryQuestion) -> Result<Self, Self::Error> {
    let mut result = vec![];

    /* Parse q_name */ {
      for word in question.q_name.split('.') {
        let len = word.len();
        #[allow(clippy::cast_possible_truncation)] let len_u8 = len as u8;
        debug_assert!(len_u8 == u8::try_from(len)?);
        result.push(len_u8);
        for i in 0..len {
          result.push(word.as_bytes()[i]);
        }
      }
    }

    /* Parse q_type */ {
      let q_type: u16 = (&question.q_type).into();
      result.extend_from_slice(&q_type.to_be_bytes());
    }

    /* Parse q_class */ {
      let q_class: u16 = (&question.q_class).into();
      result.extend_from_slice(&q_class.to_be_bytes());
    }

    Ok(result)
  }
}