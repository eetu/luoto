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
use luoto_shared::ctl::{GateStatus, VaultStatus};
use luoto_shared::policy::{CompiledRule, Rule};
use luoto_shared::{presets, profiles};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Ui;
use crate::config::{self, EnvFile};
use crate::env::{self, Ctx, UpOptions};
use crate::{commands, ctl, events, init, names, project, rules, setup, sync, workspace};

pub struct ApiError(StatusCode, Value);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<rules::Risks>() {
            Ok(rules::Risks(risks)) => ApiError(
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
    dir: Option<String>,
    /// Repositories beside the folder (`repos.rs`).
    repos: Vec<crate::repos::Listed>,
    pending: usize,
    denied_recent: usize,
    error: Option<String>,
}

#[derive(Serialize)]
struct Overview {
    instance: &'static str,
    runtime: String,
    envs: Vec<EnvRow>,
    vault: Option<VaultStatus>,
}

async fn overview(State(ui): State<Ui>) -> ApiResult<Overview> {
    let store = ui.store.clone();
    blocking(move || {
        let ctx = Ctx::load()?;
        let states = ctx.rt.states().unwrap_or_default();
        let since = Utc::now() - TimeDelta::minutes(15);
        let mut envs = Vec::new();
        for name in config::list_envs(&ctx.paths)? {
            let (dev, gate) = states.env(&name);
            let denied_recent = store.denied_since(&name, since);
            let pending = rules::requests(&ctx, &name, &states).map_or(0, |r| {
                r.iter()
                    .filter(|r| r.status == RequestStatus::Pending)
                    .count()
            });
            let (dir, error) = match EnvFile::load(&ctx.paths, &name) {
                Ok(f) => (f.cfg.workspace.dir, None),
                Err(e) => (None, Some(format!("{e:#}"))),
            };
            let repos = crate::repos::listed(&ctx, &name).unwrap_or_default();
            envs.push(EnvRow {
                name,
                dev,
                gate,
                dir,
                repos,
                pending,
                denied_recent,
                error,
            });
        }
        let vault = states
            .running(&names::vault())
            .then(|| ctl::vault_status(&ctx.rt).ok())
            .flatten();
        Ok(Overview {
            instance: names::instance(),
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
        .map(|p| json!({ "name": p.name, "description": p.description }))
        .collect();
    let agents: Vec<Value> = profiles::agent_names()
        .filter_map(profiles::agent)
        .map(|a| json!({ "name": a.name, "description": a.description }))
        .collect();
    Json(json!({ "presets": presets, "agents": agents }))
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

fn new_opts(n: NewEnv) -> init::InitOpts {
    init::InitOpts {
        dir: non_empty(n.dir),
        name: non_empty(n.name),
        presets: n.presets,
        agents: n.agents,
        ports: n.ports,
        yes: true,
        ..Default::default()
    }
}

/// What `create` would make of these choices: name, presets (each with the file that
/// suggested it) and the toolchains the folder pins. Touches nothing.
async fn detect(Json(n): Json<NewEnv>) -> ApiResult<Value> {
    blocking(move || {
        let ctx = Ctx::load()?;
        let p = init::propose(&ctx.paths, &new_opts(n))?;
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
            "project_error": p.project_error.as_deref().map(crate::text::display),
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
        let mut p = init::propose(&ctx.paths, &new_opts(n))?;
        if let Some((text, _)) = &p.project {
            check_reviewed(text, reviewed.as_deref())?;
        }
        init::create(&ctx, &mut p, true, true)?;
        init::start(&ctx, &p.name, true)?;
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
        match a.action.as_str() {
            "accept" => {
                let st = project::status(&ctx, &name)?;
                let pending = st.pending();
                let text = st
                    .text
                    .filter(|_| pending)
                    .ok_or_else(|| anyhow::anyhow!("nothing to accept"))?;
                check_reviewed(&text, a.sha.as_deref())?;
                project::apply(&ctx, &name, &text)?;
            }
            "forget" => project::ignore(&ctx, &name)?,
            other => anyhow::bail!("unknown action `{other}`"),
        }
        project::status(&ctx, &name)
    })
    .await
    .map(Json)
}

/// Every folder a pull writes, and one digest over them that applying checks.
#[derive(Serialize)]
struct PullPlans {
    plans: Vec<workspace::PullPlan>,
    digest: String,
}

fn pull_plans(ctx: &Ctx, name: &str) -> anyhow::Result<PullPlans> {
    let plans = commands::pull_targets(ctx, name, None, None)?
        .iter()
        .map(|t| workspace::plan_pull(ctx, name, t, false))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let digest = plans
        .iter()
        .map(|p| p.digest.as_str())
        .collect::<Vec<_>>()
        .join(":");
    Ok(PullPlans { plans, digest })
}

async fn pull_plan(Path(name): Path<String>) -> ApiResult<PullPlans> {
    blocking(move || pull_plans(&Ctx::load()?, &name))
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
        let all = pull_plans(&ctx, &name)?;
        if all.digest != a.digest {
            anyhow::bail!("the env's files changed since you reviewed them; review again");
        }
        let (mut written, mut skipped) = (0, 0);
        for plan in &all.plans {
            let (w, s) = workspace::apply_pull(plan, a.include_risky)?;
            written += w;
            skipped += s;
        }
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
        let (dev, gate) = ctx.rt.states().unwrap_or_default().env(&name);
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
            path: p.path.display().to_string(),
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
        rules::requests(&ctx, &name, &ctx.rt.states().unwrap_or_default())
    })
    .await
    .map(Json)
}

#[derive(Deserialize, Default)]
struct Decision {
    ttl: Option<String>,
    #[serde(default)]
    force: bool,
}

/// An approved request: the rule it became, or what an install request did.
#[derive(Serialize)]
#[serde(untagged)]
enum Approved {
    Rule(Rule),
    Installed { installed: String },
}

async fn approve(
    Path((name, id)): Path<(String, u64)>,
    Json(d): Json<Decision>,
) -> ApiResult<Approved> {
    blocking(move || {
        let ctx = Ctx::load()?;
        let req = rules::request(&ctx, &name, id)?;
        if req.install.is_some() {
            return Ok(Approved::Installed {
                installed: rules::approve_install(&ctx, &name, &req)?,
            });
        }
        rules::approve(&ctx, &name, &req, d.ttl.as_deref(), d.force).map(Approved::Rule)
    })
    .await
    .map(Json)
}

async fn reject(Path((name, id)): Path<(String, u64)>) -> ApiResult<AccessRequest> {
    blocking(move || rules::reject(&Ctx::load()?, &name, id, None))
        .await
        .map(Json)
}

#[derive(Deserialize)]
struct NewRule {
    rule: Rule,
    #[serde(default)]
    force: bool,
}

async fn add_rule(Path(name): Path<String>, Json(n): Json<NewRule>) -> ApiResult<Rule> {
    blocking(move || rules::add_rule_checked(&Ctx::load()?, &name, n.rule, n.force))
        .await
        .map(Json)
}

async fn delete_rule(Path((name, id)): Path<(String, String)>) -> ApiResult<usize> {
    blocking(move || rules::remove(&Ctx::load()?, &name, &id))
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
                    quiet: true,
                    ..Default::default()
                },
            )?,
            "down" => env::down(&ctx, &name)?,
            "rebuild" => {
                env::remove_dev(&ctx, &name)?;
                env::up(
                    &ctx,
                    &name,
                    &UpOptions {
                        quiet: true,
                        ..Default::default()
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
                let n = sync::unlock_all(&ctx)?;
                Ok(json!({ "envs": n }))
            }
            "lock" => {
                let failed = sync::lock_all(&ctx)?;
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
