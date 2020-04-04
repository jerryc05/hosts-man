use crate::dns_query::dns_query_0_header::DnsQueryHeader;
use crate::dns_query::dns_query_1_question::DnsQueryQuestion;
use crate::dns_query::dns_query_2_answer::DnsQueryAnswer;
use crate::dns_query::dns_query_3_authority::DnsQueryAuthority;
use crate::dns_query::dns_query_4_additional::DnsQueryAdditional;

/// https://tools.ietf.org/html/rfc1035
#[derive(Debug)]
pub(crate) struct DnsQuery {
  pub(crate) header: DnsQueryHeader,
  pub(crate) question: DnsQueryQuestion,
  pub(crate) answer: DnsQueryAnswer,
  pub(crate) authority: DnsQueryAuthority,
  pub(crate) additional: DnsQueryAdditional,
}