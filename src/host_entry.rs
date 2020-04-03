use std::net::IpAddr;
use std::path::Path;
use std::fs::read_to_string;
use std::borrow::Cow;
use std::str::FromStr;

#[derive(Debug)]
pub(crate) struct HostEntry<'a, 'b> {
  ip: IpAddr,
  host: Cow<'a, str>,
  desc_no_pound_sign: Cow<'b, str>,
}

static mut HOSTS_PATH: Option<&Path> = None;

fn hosts_path() -> &'static Path {
  if let Some(path) = unsafe { HOSTS_PATH } {
    return path;
  }

  let mut path;

  if cfg!(windows) {
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
  } else {
    path = Path::new("/etc/hosts");
    if !path.is_file() {
      panic!("Cannot locate \"hosts\" file!")
    }
  }
  unsafe { HOSTS_PATH = Some(path); }
  path
}

pub(crate) fn parse_hosts<'a, 'b>() -> Vec<HostEntry<'a, 'b>> {
  let mut host_entries = vec![];

  for line in read_to_string(hosts_path()).unwrap()
                                          .split_terminator('\n') {
    let mut ip_splitter = line.trim().splitn(2, ' ');

    /* Parse IP */
    let ip;
    {
      match ip_splitter.next() {
        Some(ip_) => ip = ip_,
        None => {
          eprintln!("IP does not exist [{}]!", line);
          continue;
        }
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
      host: host.trim().to_owned().into(),
      desc_no_pound_sign: desc.trim().to_owned().into(),
    })
  }
  host_entries
}