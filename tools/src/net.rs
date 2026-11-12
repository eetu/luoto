//! `sandbox net`: the dev end of the tun link of an env without a network card (started by
//! init.sh as root when `LUOTO_NET=tun`). Creates tun0 to the gate, routes everything
//! through it, then pumps its packets over the socket the host connects to.

use std::path::Path;

use anyhow::Result;

#[cfg(target_os = "linux")]
pub fn serve(socket: &Path) -> Result<()> {
    use anyhow::Context;
    use luoto_shared::tun;

    let dev = tun::create(tun::NAME, tun::DEV_ADDR, tun::GATE_ADDR).context("create tun0")?;
    tun::default_route(tun::NAME).context("route through tun0")?;
    let listener = tun::listen(socket).with_context(|| format!("bind {}", socket.display()))?;
    tun::serve(dev, listener, None).context("tun link")
}

#[cfg(not(target_os = "linux"))]
pub fn serve(_socket: &Path) -> Result<()> {
    anyhow::bail!("the tun link runs only on Linux")
}
