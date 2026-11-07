//! Gate configuration from the environment luoto sets on the container.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use luoto_shared::{PROXY_PORT, TRANSPARENT_PORT};

#[derive(Debug, Clone)]
pub struct Config {
    pub env: String,
    /// The gate's address on the env's internal network; every sandbox-facing listener
    /// binds here and nowhere else.
    pub gate_ip: IpAddr,
    pub proxy_addr: SocketAddr,
    pub internal_subnet: Option<String>,
    pub state_dir: PathBuf,
    /// Dev-server ports to relay from the gate's published side to the dev container.
    pub forwards: Vec<u16>,
    pub dev_ip: Option<IpAddr>,
    /// Install iptables rules and run the transparent catch-all (needs NET_ADMIN).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub transparent: bool,
    pub dns: bool,
    /// Extra PEM roots trusted for upstream TLS (corporate TLS inspection upstream).
    pub upstream_ca: Option<PathBuf>,
    /// More roots for upstream TLS, as PEM: the CAs of self-hosted forges the env reaches.
    pub upstream_ca_pem: Option<String>,
    /// Drop to this uid/gid after binding sockets (Linux).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub run_as: Option<u32>,
    #[cfg(feature = "test-hooks")]
    pub test_resolve: Vec<(String, SocketAddr)>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn flag(name: &str, default: bool) -> bool {
    var(name).map_or(default, |v| v == "1" || v == "true")
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let env = var("LUOTO_ENV").unwrap_or_else(|| "default".into());
        let gate_ip: IpAddr = var("LUOTO_GATE_IP")
            .map(|v| v.parse())
            .transpose()
            .context("LUOTO_GATE_IP")?
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let proxy_addr = match var("LUOTO_PROXY_ADDR") {
            Some(a) => a.parse().context("LUOTO_PROXY_ADDR")?,
            None => SocketAddr::new(gate_ip, PROXY_PORT),
        };
        let forwards = var("LUOTO_FORWARDS")
            .map(|v| {
                v.split(',')
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.trim().parse::<u16>().context("LUOTO_FORWARDS"))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Config {
            env,
            gate_ip,
            proxy_addr,
            internal_subnet: var("LUOTO_INTERNAL_SUBNET"),
            state_dir: var("LUOTO_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/luoto-gate")),
            forwards,
            dev_ip: var("LUOTO_DEV_IP")
                .map(|v| v.parse())
                .transpose()
                .context("LUOTO_DEV_IP")?,
            transparent: flag("LUOTO_TRANSPARENT", false),
            dns: flag("LUOTO_DNS", false),
            upstream_ca: var("LUOTO_UPSTREAM_CA").map(PathBuf::from),
            upstream_ca_pem: var("LUOTO_UPSTREAM_CA_PEM"),
            run_as: var("LUOTO_RUN_AS")
                .map(|v| v.parse())
                .transpose()
                .context("LUOTO_RUN_AS")?,
            #[cfg(feature = "test-hooks")]
            test_resolve: var("LUOTO_TEST_RESOLVE")
                .map(|v| {
                    v.split(',')
                        .filter_map(|pair| {
                            let (h, a) = pair.split_once('=')?;
                            Some((h.to_string(), a.parse().ok()?))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn transparent_addr(&self) -> SocketAddr {
        SocketAddr::new(self.gate_ip, TRANSPARENT_PORT)
    }

    pub fn dns_addr(&self) -> SocketAddr {
        SocketAddr::new(self.gate_ip, 53)
    }
}
