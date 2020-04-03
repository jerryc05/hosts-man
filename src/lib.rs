use crate::host_entry::*;
use crate::tcping::*;
use std::net::SocketAddr;

mod host_entry;
mod tcping;

pub fn start() {
  let entries = parse_hosts();
  println!("{}", entries);

  for entry in entries.as_ref() {
    tcping(SocketAddr::new(entry.ip, 443));
  }
}