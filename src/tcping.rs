use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

pub(crate) fn tcping(ip: SocketAddr) -> u128 {
  let start = Instant::now();
  TcpStream::connect(ip).unwrap();
  return start.elapsed().as_millis();
}