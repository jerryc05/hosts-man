use std::net::IpAddr;
use std::path::Path;
use std::fs::read_to_string;
use std::str::FromStr;
use std::fmt::{Display, Formatter};
use std::io::Error;

pub(crate) struct HostEntryVec(Vec<HostEntry>);

#[derive(Debug)]
pub(crate) struct HostEntry {
  pub(crate) ip: IpAddr,
  pub(crate) host: String,
  desc_no_pound_sign: String,
}

const DISPLAY_WIDTH: usize = 64;

impl Display for HostEntryVec {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    let vec = &self.0;

    writeln!(f, "{:-^1$}", "Start of Hosts list", DISPLAY_WIDTH)?;
    for (i, entry) in vec.iter().enumerate() {
      writeln!(f, "{:2}: IP: {:?}", i + 1, entry.ip)?;
      writeln!(f, "\tHost: {}", entry.host)?;
      if !entry.desc_no_pound_sign.is_empty() {
        writeln!(f, "\tDesc: {}", entry.desc_no_pound_sign)?;
      }
    }
    write!(f, "{:-^1$}", "End of hosts list", DISPLAY_WIDTH)?;
    Ok(())
  }
}

impl AsRef<Vec<HostEntry>> for HostEntryVec {
  fn as_ref(&self) -> &Vec<HostEntry> {
    &self.0
  }
}

pub(crate) fn parse_hosts() -> Result<HostEntryVec,Error> {
  let mut host_entries = vec![];

  for line in read_to_string(hosts_path())?.split_terminator('\n') {
    let mut ip_splitter = line.trim().splitn(2, ' ');

    /* Parse IP */
    let ip;
    {
      if let Some(ip_) = ip_splitter.next() {
        ip = ip_
      } else {
        eprintln!("IP does not exist [{}]!", line);
        continue;
      }
    }

    /* Parse host and desc */
    let host;
    let desc;
    {
      let host_n_desc;
      match ip_splitter.next() {
        Some(host_n_desc_) => host_n_desc = host_n_desc_,
        None => {
          eprintln!("Invalid host and desc [{}]!", line);
          continue;
        }
      }

      let mut host_splitter = host_n_desc.splitn(2, '#');
      match host_splitter.next() {
        Some(host_) => {
          host = host_;
          desc = host_splitter.next().unwrap_or("")
        }
        None => {
          host = host_n_desc;
          desc = "";
        }
      }
    }

    host_entries.push(HostEntry {
      ip: IpAddr::from_str(&ip.to_owned()).unwrap(),
      host: host.trim().to_owned(),
      desc_no_pound_sign: desc.trim().to_owned(),
    })
  }
  Ok(HostEntryVec(host_entries))
}

fn hosts_path() -> &'static Path {
  static mut HOSTS_PATH: Option<&Path> = None;

  if unsafe { HOSTS_PATH } == None {
    let mut path;

    #[cfg(windows)] {
      path = Path::new("C:/Windows/System32/drivers/etc/hosts");

      if !path.is_file() {
        path = Path::new("C:/WinNT/System32/drivers/etc/hosts");
      }

      if !path.is_file() {
        path = Path::new("C:/Windows/hosts");
      }

      if !path.is_file() {
        panic!("Cannot locate \"hosts\" file!")
      }
    }

    #[cfg(not(windows))] {
      path = Path::new("/etc/hosts");
      if !path.is_file() {
        panic!("Cannot locate \"hosts\" file!")
      }
    }
    unsafe { HOSTS_PATH = Some(path); }
  }
  unsafe { HOSTS_PATH }.unwrap()
}