use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Instant, Duration};

#[inline]
pub(crate) fn tcping<T: ToSocketAddrs>(ip: T) -> Duration {
  let start = Instant::now();
  TcpStream::connect(ip).unwrap();
  start.elapsed()
}