//! JSON API for the UI. Handlers call the same core functions as the CLI; anything that
//! shells out to the runtime runs on the blocking pool.

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{TimeDelta, Utc};
use futures_util::Stream;
use luoto_shared::api::{AccessRequest, RequestStatus};
use luoto_shared::ctl::{GateCtl, GateStatus, VaultStatus};
use luoto_shared::events::Verdict;
use luoto_shared::policy::{CompiledRule, Rule};
use luoto_shared::{presets, profiles};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Ui;
use crate::config::{self, EnvFile, new_rule_id};
use crate::env::{self, Ctx, UpOptions};
use crate::{commands, ctl, events, names, project, setup, workspace};

pub struct ApiError(StatusCode, Value);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<commands::Risks>() {
            Ok(commands::Risks(risks)) => ApiError(
                StatusCode::CONFLICT,
                json!({ "error": "confirm risks", "risks": risks }),
            ),
            Err(e) => ApiError(
                StatusCode::BAD_REQUEST,
                json!({ "error": format!("{e:#}") }),
            ),
        }
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r.map_err(ApiError::from),
        Err(e) => Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": e.to_string() }),
        )),
    }
}

pub fn routes() -> Router<Ui> {
    Router::new()
        .route("/overview", get(overview))
        .route("/meta", get(meta))
        .route("/setup", get(setup_info))
        .route("/setup/install", post(setup_install))
        .route("/envs", post(create_env))
        .route("/detect", post(detect))
        .route("/envs/{name}", get(env_detail))
        .route("/envs/{name}/egress", get(egress))
        .route("/envs/{name}/events", get(env_events))
        .route("/envs/{name}/requests", get(requests))
        .route("/envs/{name}/requests/{id}/approve", post(approve))
        .route("/envs/{name}/requests/{id}/reject", post(reject))
        .route("/envs/{name}/rules", post(add_rule))
        .route("/envs/{name}/rules/{id}", delete(delete_rule))
        .route(
            "/envs/{name}/project",
            get(project_status).post(project_action),
        )
        .route("/envs/{name}/pull", get(pull_plan).post(pull_apply))
        .route("/envs/{name}/{action}", post(env_action))
        .route("/vault/{action}", post(vault_action))
        .route("/stream", get(stream))
}

#[derive(Serialize)]
struct EnvRow {
    name: String,
    dev: String,
    gate: String,
    image: String,
    presets: Vec<String>,
    agents: Vec<String>,
    ports: Vec<u16>,
    dir: Option<String>,
    pending: usize,
    denied_recent: usize,
    error: Option<String>,
}

#[derive(Serialize)]
struct Overview {
    runtime: String,
    envs: Vec<EnvRow>,
    vault: Option<VaultStatus>,
}

async fn overview(State(ui): State<Ui>) -> ApiResult<Overview> {
    let store = ui.store.clone();
    blocking(move || {
        let ctx = Ctx::load()?;
        let mut envs = Vec::new();
        for name in config::list_envs(&ctx.paths)? {
            let (dev, gate) = env::status_line(&ctx, &name);
            let since = Utc::now() - TimeDelta::minutes(15);
            let denied_recent = store
                .query(&name, since, None, 5000)
                .iter()
                .filter(|e| {
                    e.verdict == Some(Verdict::Deny)
                        && !e
                            .host
                            .as_deref()
                            .is_some_and(luoto_shared::events::is_selftest)
                })
                .count();
            let pending = if gate == "running" {
                ctl::gate::<Vec<AccessRequest>>(&ctx.rt, &name, &GateCtl::Requests)
                    .map(|r| {
                        r.iter()
                            .filter(|r| r.status == RequestStatus::Pending)
                            .count()
                    })
                    .unwrap_or(0)
            } else {
                0
            };
            let row = match EnvFile::load(&ctx.paths, &name) {
                Ok(f) => EnvRow {
                    image: env::env_image(&ctx, &f.cfg),
                    presets: f.cfg.presets.clone(),
                    agents: f.cfg.agents.clone(),
                    ports: f.cfg.ports.clone(),
                    dir: f.cfg.workspace.dir.clone(),
                    name: name.clone(),
                    dev,
                    gate,
                    pending,
                    denied_recent,
                    error: None,
                },
                Err(e) => EnvRow {
                    name: name.clone(),
                    dev,
                    gate,
                    image: String::new(),
                    presets: vec![],
                    agents: vec![],
                    ports: vec![],
                    dir: None,
                    pending,
                    denied_recent,
                    error: Some(format!("{e:#}")),
                },
            };
            envs.push(row);
        }
        let vault = (ctx.rt.container_state(names::VAULT).as_deref() == Some("running"))
            .then(|| ctl::vault_status(&ctx.rt).ok())
            .flatten();
        Ok(Overview {
            runtime: ctx
                .rt
                .version()
                .unwrap_or_else(|_| ctx.rt.name().to_string()),
            envs,
            vault,
        })
    })
    .await
    .map(Json)
}

async fn meta() -> Json<Value> {
    let presets: Vec<Value> = presets::all()
        .into_iter()
        .map(|p| json!({ "name": p.name, "description": p.description, "hosts": p.rules.iter().map(|r| r.host.clone()).collect::<Vec<_>>() }))
        .collect();
    let agents: Vec<Value> = profiles::agent_names()
        .filter_map(profiles::agent)
        .map(|a| json!({ "name": a.name, "description": a.description, "providers": a.providers }))
        .collect();
    let providers: Vec<Value> = profiles::provider_names()
        .filter_map(profiles::provider)
        .map(|p| json!({ "name": p.name, "description": p.description, "host": p.host, "kinds": p.auth.keys().collect::<Vec<_>>() }))
        .collect();
    Json(json!({ "presets": presets, "agents": agents, "providers": providers }))
}

async fn setup_info() -> ApiResult<Value> {
    blocking(|| {
        let d = setup::detect();
        let r = setup::recommend(&d);
        let images_ok = Ctx::load()
            .map(|ctx| {
                ["gate", "vault", "tools"]
                    .iter()
                    .all(|c| ctx.rt.image_exists(&ctx.image(c)))
            })
            .unwrap_or(false);
        Ok(json!({ "detection": d, "recommendation": r, "images_ok": images_ok }))
    })
    .await
    .map(Json)
}

async fn setup_install() -> ApiResult<Value> {
    blocking(|| {
        let r = setup::recommend(&setup::detect());
        let Some(cmd) = r.install else {
            anyhow::bail!("nothing to install");
        };
        if cmd[0] == "sudo" {
            anyhow::bail!("this needs your password — run it in a terminal: {}", cmd.join(" "));
        }
        let out = std::process::Command::new(&cmd[0]).args(&cmd[1..]).output()?;
        Ok(json!({
            "ok": out.status.success(),
            "command": cmd.join(" "),
            "output": format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)),
        }))
    })
    .await
    .map(Json)
}

#[derive(Deserialize)]
struct NewEnv {
    name: Option<String>,
    dir: Option<String>,
    image: Option<String>,
    #[serde(default)]
    presets: Vec<String>,
    #[serde(default)]
    agents: Vec<String>,
    #[serde(default)]
    ports: Vec<u16>,
    /// `project_sha` from `detect`: the luoto.toml the user saw, which creating accepts.
    project_sha: Option<String>,
}

/// The luoto.toml `text` is the one the user reviewed (`reviewed` is the sha they were shown).
fn check_reviewed(text: &str, reviewed: Option<&str>) -> anyhow::Result<()> {
    match reviewed {
        Some(s) if s == project::sha(text) => Ok(()),
        Some(_) => anyhow::bail!("luoto.toml changed since you reviewed it; review it again"),
        None => anyhow::bail!("there is a luoto.toml you haven't reviewed; review it first"),
    }
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn new_opts(n: NewEnv) -> commands::InitOpts {
    commands::InitOpts {
        dir: non_empty(n.dir),
        name: non_empty(n.name),
        image: non_empty(n.image),
        presets: n.presets,
        tools: Vec::new(),
        agents: n.agents,
        ports: n.ports,
        isolation: None,
        no_up: false,
        yes: true,
        no_project: false,
    }
}

/// What `create` would make of these choices: name, presets (each with the file that
/// suggested it) and the toolchains the folder pins. Touches nothing.
async fn detect(Json(n): Json<NewEnv>) -> ApiResult<Value> {
    blocking(move || {
        let ctx = Ctx::load()?;
        let p = commands::propose(&ctx.paths, &new_opts(n))?;
        let presets: Vec<Value> = p
            .cfg
            .presets
            .iter()
            .map(|name| {
                let reason = p
                    .found
                    .presets
                    .iter()
                    .find(|(f, _)| f == name)
                    .map(|(_, r)| r);
                json!({ "name": name, "reason": reason })
            })
            .collect();
        Ok(json!({
            "name": p.name,
            "new_folder": p.new_folder,
            "presets": presets,
            "tools": p.found.tools,
            "project": p.project.as_ref().map(|(_, pc)| project::summary(pc)),
            "project_sha": p.project.as_ref().map(|(text, _)| project::sha(text)),
            "project_error": p.project_error.as_deref().map(project::clean),
        }))
    })
    .await
    .map(Json)
}

async fn create_env(Json(n): Json<NewEnv>) -> ApiResult<Value> {
    blocking(move || {
        let ctx = Ctx::load()?;
        if non_empty(n.dir.clone()).is_none() {
            anyhow::bail!("choose the project's folder (a new one is created)");
        }
        let reviewed = n.project_sha.clone();
        let mut o = new_opts(n);
        let mut p = commands::propose(&ctx.paths, &o)?;
        if let Some((text, _)) = &p.project {
            check_reviewed(text, reviewed.as_deref())?;
        }
        commands::make_folder(&mut p)?;
        EnvFile::create(&ctx.paths, &p.name, &p.cfg)?;
        if let Some((text, pc)) = &p.project {
            project::accept(&ctx, &p.name, text)?;
            for a in &pc.agents {
                if !o.agents.contains(a) {
                    o.agents.push(a.clone());
                }
            }
        }
        env::up(
            &ctx,
            &p.name,
            &UpOptions {
                selftest: true,
                quiet: true,
            },
        )?;
        for a in &o.agents {
            crate::agents::install(&ctx, &p.name, a)?;
        }
        Ok(json!({ "ok": true, "name": p.name }))
    })
    .await
    .map(Json)
}

async fn project_status(Path(name): Path<String>) -> ApiResult<project::Status> {
    blocking(move || project::status(&Ctx::load()?, &name))
        .await
        .map(Json)
}

#[derive(Deserialize)]
struct ProjectAction {
    /// `accept` the current luoto.toml, or `forget` it.
    action: String,
    /// The status's `sha`: accept applies only the text the user reviewed.
    sha: Option<String>,
}

async fn project_action(
    Path(name): Path<String>,
    Json(a): Json<ProjectAction>,
) -> ApiResult<project::Status> {
    blocking(move || {
        let ctx = Ctx::load()?;
        let st = project::status(&ctx, &name)?;
        match a.action.as_str() {
            "accept" => {
                let text = st
                    .text
                    .filter(|_| matches!(st.state, "changed" | "new" | "declined"))
                    .ok_or_else(|| anyhow::anyhow!("nothing to accept"))?;
                check_reviewed(&text, a.sha.as_deref())?;
                project::accept(&ctx, &name, &text)?;
                env::up(
                    &ctx,
                    &name,
                    &UpOptions {
                        selftest: true,
                        quiet: true,
                    },
                )?;
            }
            "forget" => {
                project::forget(&ctx, &name, st.text.as_deref())?;
                env::reapply(&ctx, &name)?;
            }
            other => anyhow::bail!("unknown action `{other}`"),
        }
        project::status(&ctx, &name)
    })
    .await
    .map(Json)
}

fn pull_dest(ctx: &Ctx, name: &str) -> anyhow::Result<std::path::PathBuf> {
    let f = EnvFile::load(&ctx.paths, name)?;
    let dir = f
        .cfg
        .workspace
        .dir
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("this env has no folder to pull into"))?;
    workspace::canonical(dir)
}

async fn pull_plan(Path(name): Path<String>) -> ApiResult<workspace::PullPlan> {
    blocking(move || {
        let ctx = Ctx::load()?;
        let dest = pull_dest(&ctx, &name)?;
        workspace::plan_pull(&ctx, &name, &dest, false)
    })
    .await
    .map(Json)
}

#[derive(Deserialize)]
struct PullApply {
    digest: String,
    #[serde(default)]
    include_risky: bool,
}

async fn pull_apply(Path(name): Path<String>, Json(a): Json<PullApply>) -> ApiResult<Value> {
    blocking(move || {
        let ctx = Ctx::load()?;
        let dest = pull_dest(&ctx, &name)?;
        let plan = workspace::plan_pull(&ctx, &name, &dest, false)?;
        if plan.digest != a.digest {
            anyhow::bail!("the env's files changed since you reviewed them; review again");
        }
        let (written, skipped) = workspace::apply_pull(&plan, a.include_risky)?;
        Ok(json!({ "written": written, "skipped": skipped }))
    })
    .await
    .map(Json)
}

#[derive(Serialize)]
struct Injected {
    host: String,
    binding: String,
}

#[derive(Serialize)]
struct EnvDetail {
    name: String,
    path: String,
    rules: Vec<CompiledRule>,
    injections: Vec<Injected>,
    denies: usize,
    warnings: Vec<String>,
    dev: String,
    gate: String,
    gate_status: Option<GateStatus>,
    credentials: Vec<String>,
    missing_secrets: Vec<String>,
    sandbox_secrets: Vec<String>,
}

async fn env_detail(Path(name): Path<String>) -> ApiResult<EnvDetail> {
    blocking(move || {
        let ctx = Ctx::load()?;
        let p = env::plan(&ctx, &name)?;
        let (dev, gate) = env::status_line(&ctx, &name);
        let gate_status = (gate == "running")
            .then(|| ctl::gate_status(&ctx.rt, &name).ok())
            .flatten();
        let vault_env = ctl::vault_status(&ctx.rt)
            .ok()
            .and_then(|v| v.envs.into_iter().find(|e| e.env == name));
        let mut injections: Vec<Injected> = p
            .compiled
            .policy
            .injections
            .iter()
            .map(|i| Injected {
                host: i.host.clone(),
                binding: i.binding.clone(),
            })
            .collect();
        injections.dedup_by(|a, b| a.host == b.host && a.binding == b.binding);
        Ok(EnvDetail {
            path: p.file.path.display().to_string(),
            rules: p.compiled.policy.rules.clone(),
            denies: p.compiled.policy.denies.len(),
            warnings: p.compiled.warnings.clone(),
            credentials: p.compiled.bindings.keys().cloned().collect(),
            missing_secrets: vault_env.map(|v| v.missing).unwrap_or_default(),
            sandbox_secrets: p.compiled.sandbox_refs.keys().cloned().collect(),
            injections,
            name,
            dev,
            gate,
            gate_status,
        })
    })
    .await
    .map(Json)
}

#[derive(Deserialize)]
struct Since {
    /// Minutes back (default one day).
    minutes: Option<i64>,
    host: Option<String>,
}

async fn egress(
    State(ui): State<Ui>,
    Path(name): Path<String>,
    Query(q): Query<Since>,
) -> ApiResult<Vec<events::HostSummary>> {
    let since = Utc::now() - TimeDelta::minutes(q.minutes.unwrap_or(1440));
    let evs = ui.store.query(&name, since, None, 50_000);
    Ok(Json(events::summarize(&evs)))
}

async fn env_events(
    State(ui): State<Ui>,
    Path(name): Path<String>,
    Query(q): Query<Since>,
) -> ApiResult<Vec<luoto_shared::events::Event>> {
    let since = Utc::now() - TimeDelta::minutes(q.minutes.unwrap_or(1440));
    Ok(Json(ui.store.query(&name, since, q.host.as_deref(), 200)))
}

async fn requests(Path(name): Path<String>) -> ApiResult<Vec<AccessRequest>> {
    blocking(move || {
        let ctx = Ctx::load()?;
        if ctx.rt.container_state(&names::gate(&name)).as_deref() != Some("running") {
            return Ok(Vec::new());
        }
        ctl::gate(&ctx.rt, &name, &GateCtl::Requests)
    })
    .await
    .map(Json)
}

#[derive(Deserialize, Default)]
struct Decision {
    ttl: Option<String>,
    note: Option<String>,
    #[serde(default)]
    force: bool,
}

async fn approve(
    Path((name, id)): Path<(String, u64)>,
    Json(d): Json<Decision>,
) -> ApiResult<Rule> {
    blocking(move || {
        let ctx = Ctx::load()?;
        commands::approve_request(&ctx, &name, id, d.ttl.as_deref(), d.force)
    })
    .await
    .map(Json)
}

async fn reject(
    Path((name, id)): Path<(String, u64)>,
    Json(d): Json<Decision>,
) -> ApiResult<AccessRequest> {
    blocking(move || {
        let ctx = Ctx::load()?;
        ctl::gate(
            &ctx.rt,
            &name,
            &GateCtl::Resolve {
                id,
                approved: false,
                note: d.note,
            },
        )
    })
    .await
    .map(Json)
}

#[derive(Deserialize)]
struct NewRule {
    rule: Rule,
    #[serde(default)]
    force: bool,
}

async fn add_rule(
    Path(name): Path<String>,
    Json(n): Json<NewRule>,
) -> Result<Json<Rule>, ApiError> {
    let mut rule = n.rule;
    if rule.id.is_none() {
        rule.id = Some(new_rule_id());
    }
    blocking(move || {
        commands::add_rule_checked(&Ctx::load()?, &name, rule.clone(), n.force)?;
        Ok(rule)
    })
    .await
    .map(Json)
}

async fn delete_rule(Path((name, id)): Path<(String, String)>) -> ApiResult<usize> {
    blocking(move || {
        let ctx = Ctx::load()?;
        let mut f = EnvFile::load(&ctx.paths, &name)?;
        let n = f.remove_rules(&id)?;
        if n == 0 {
            anyhow::bail!("no user rule `{id}`");
        }
        env::reapply(&ctx, &name)?;
        Ok(n)
    })
    .await
    .map(Json)
}

async fn env_action(Path((name, action)): Path<(String, String)>) -> ApiResult<Value> {
    blocking(move || {
        let ctx = Ctx::load()?;
        match action.as_str() {
            "up" => env::up(
                &ctx,
                &name,
                &UpOptions {
                    selftest: true,
                    quiet: true,
                },
            )?,
            "down" => env::down(&ctx, &name)?,
            "rebuild" => {
                env::remove_dev(&ctx, &name)?;
                env::up(
                    &ctx,
                    &name,
                    &UpOptions {
                        selftest: true,
                        quiet: true,
                    },
                )?;
            }
            "selftest" => {
                let r = env::selftest(&ctx, &name, None)?;
                return Ok(serde_json::to_value(r)?);
            }
            other => anyhow::bail!("unknown action `{other}`"),
        }
        Ok(json!({ "ok": true }))
    })
    .await
    .map(Json)
}

async fn vault_action(Path(action): Path<String>) -> ApiResult<Value> {
    blocking(move || {
        let ctx = Ctx::load()?;
        match action.as_str() {
            "unlock" => {
                let n = env::unlock_all(&ctx)?;
                Ok(json!({ "envs": n }))
            }
            "lock" => {
                let failed = env::lock_all(&ctx)?;
                if !failed.is_empty() {
                    anyhow::bail!("lock incomplete: {}", failed.join("; "));
                }
                Ok(json!({ "ok": true }))
            }
            other => anyhow::bail!("unknown action `{other}`"),
        }
    })
    .await
    .map(Json)
}

async fn stream(State(ui): State<Ui>) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = ui.store.tx.subscribe();
    let s = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let data = serde_json::to_string(&ev).unwrap_or_default();
                    return Some((Ok(SseEvent::default().data(data)), rx));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(s).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_reviewed_luoto_toml() {
        let text = "presets = [\"npm\"]\n";
        assert!(check_reviewed(text, Some(&project::sha(text))).is_ok());
        let swapped = check_reviewed("presets = [\"pypi\"]\n", Some(&project::sha(text)));
        assert!(format!("{:#}", swapped.unwrap_err()).contains("changed since you reviewed"));
        assert!(check_reviewed(text, None).is_err());
    }
}
