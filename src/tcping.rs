use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

pub(crate) fn tcping(ip: SocketAddr) {
  let start = Instant::now();
  TcpStream::connect(ip).unwrap();
  let ms = start.elapsed().as_millis();
  println!("{:3} ms: {}", ms, ip);
}