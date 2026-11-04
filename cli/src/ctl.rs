//! Talking to the gate and vault control sockets through the runtime's `exec -i`.

use anyhow::{Context, Result, bail};
use luoto_shared::ctl::{CtlResponse, GateCtl, GateStatus, VaultCtl, VaultStatus};
use serde::de::DeserializeOwned;

use crate::names;
use crate::runtime::Runtime;

fn call<T: DeserializeOwned>(
    rt: &Runtime,
    container: &str,
    argv: &[&str],
    body: String,
) -> Result<T> {
    let mut args = vec!["exec", "-i", container];
    args.extend_from_slice(argv);
    let out = match rt.run_stdin(&args, format!("{body}\n").as_bytes()) {
        Ok(o) => o,
        Err(e) => {
            // ctl prints a JSON error body with a non-zero exit; surface it if present.
            let msg = e.to_string();
            if let Some(start) = msg.find('{')
                && let Ok(r) = serde_json::from_str::<CtlResponse>(&msg[start..])
            {
                bail!("{container}: {}", r.error.unwrap_or_default());
            }
            return Err(e).with_context(|| format!("control {container}"));
        }
    };
    let resp: CtlResponse =
        serde_json::from_str(out.trim()).with_context(|| format!("{container} control reply"))?;
    if !resp.ok {
        bail!("{container}: {}", resp.error.unwrap_or_default());
    }
    serde_json::from_value(resp.data).with_context(|| format!("{container} control data"))
}

pub fn gate<T: DeserializeOwned>(rt: &Runtime, env: &str, op: &GateCtl) -> Result<T> {
    call(
        rt,
        &names::gate(env),
        &["/usr/local/bin/luoto-gate", "ctl"],
        serde_json::to_string(op)?,
    )
}

pub fn vault<T: DeserializeOwned>(rt: &Runtime, op: &VaultCtl) -> Result<T> {
    call(
        rt,
        names::VAULT,
        &["/luoto-vault", "ctl"],
        serde_json::to_string(op)?,
    )
}

pub fn gate_status(rt: &Runtime, env: &str) -> Result<GateStatus> {
    gate(rt, env, &GateCtl::Status)
}

pub fn vault_status(rt: &Runtime) -> Result<VaultStatus> {
    vault(rt, &VaultCtl::Status)
}
