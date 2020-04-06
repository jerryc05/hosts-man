#![feature(try_trait)]

use crate::host_entry::parse_hosts;
use crate::tcping::tcping;
use std::net::SocketAddr;

mod host_entry;
mod tcping;
mod dns_query;

pub fn start() {
  let entries = parse_hosts().unwrap();
  println!("{}", entries);

  for entry in entries.as_ref() {
    let dur = tcping(SocketAddr::new(entry.ip, 80));
    println!("{:#12?}: {:19} {}", dur, entry.ip, entry.host);
    // println!("{:?}\n", lookup_host(entry.host.as_ref()).unwrap());
  }
}