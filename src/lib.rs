use crate::host_entry::parse_hosts;

mod host_entry;

pub fn start() {
  let entries = parse_hosts();
  println!("{}", entries);
}