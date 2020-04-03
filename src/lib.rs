use crate::host_entry::*;
use crate::tcping::*;
use std::net::SocketAddr;
use dns_lookup::lookup_host;

mod host_entry;
mod tcping;

pub fn start() {
  let entries = parse_hosts();
  println!("{}", entries);

  for entry in entries.as_ref() {
    let ms = tcping(SocketAddr::new(entry.ip, 443));
    println!("{:3} ms: {:19} {}", ms, entry.ip, entry.host);
    println!("{:?}\n", lookup_host(entry.host.as_ref()).unwrap());
  }
}