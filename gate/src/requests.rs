//! Access requests filed from inside the sandbox. Only the host resolves them; the sandbox
//! gets a bounded queue so requests can't be used to wear the user down.

use chrono::Utc;
use luoto_shared::api::{
    AccessRequest, MAX_PENDING_REQUESTS, MAX_REASON_LEN, NewAccessRequest, RequestStatus,
};
use luoto_shared::host::normalize_host;
use luoto_shared::policy::AccessLevel;
use luoto_shared::policy::{Access, Rule, RuleOrigin, rule_error};

const KEEP: usize = 100;

#[derive(Default)]
pub struct Requests {
    next: u64,
    items: Vec<AccessRequest>,
}

fn clean_reason(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(MAX_REASON_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

impl Requests {
    pub fn create(&mut self, new: NewAccessRequest) -> Result<AccessRequest, String> {
        if let Some(install) = &new.install {
            install.check()?;
            let reason = clean_reason(&new.reason);
            if reason.is_empty() {
                return Err("a reason is required".into());
            }
            if let Some(existing) = self
                .items
                .iter()
                .find(|r| r.status == RequestStatus::Pending && r.install.as_ref() == Some(install))
            {
                return Ok(existing.clone());
            }
            return self.file(AccessRequest {
                id: 0,
                host: String::new(),
                access: AccessLevel::Read,
                paths: Vec::new(),
                reason,
                status: RequestStatus::Pending,
                created: Utc::now(),
                resolved: None,
                note: None,
                install: Some(install.clone()),
            });
        }
        let host = match new.host.strip_prefix("*.") {
            Some(rest) => format!("*.{}", normalize_host(rest).map_err(|e| e.to_string())?),
            None => normalize_host(&new.host).map_err(|e| e.to_string())?,
        };
        let rule = Rule {
            host: host.clone(),
            access: Access::Level(new.access),
            paths: new.paths.clone(),
            ..Default::default()
        };
        if let Some(e) = rule_error(&rule, RuleOrigin::Sandbox) {
            return Err(e.message);
        }
        let reason = clean_reason(&new.reason);
        if reason.is_empty() {
            return Err("a reason is required".into());
        }
        if let Some(existing) = self.items.iter().find(|r| {
            r.status == RequestStatus::Pending && r.host == host && r.access == new.access
        }) {
            return Ok(existing.clone());
        }
        self.file(AccessRequest {
            id: 0,
            host,
            access: new.access,
            paths: new.paths,
            reason,
            status: RequestStatus::Pending,
            created: Utc::now(),
            resolved: None,
            note: None,
            install: None,
        })
    }

    /// Queue `req` under the next id, unless too many wait already.
    fn file(&mut self, mut req: AccessRequest) -> Result<AccessRequest, String> {
        let pending = self
            .items
            .iter()
            .filter(|r| r.status == RequestStatus::Pending)
            .count();
        if pending >= MAX_PENDING_REQUESTS {
            return Err(format!(
                "{pending} requests are already waiting for the user; wait for them to be resolved"
            ));
        }
        self.next += 1;
        req.id = self.next;
        self.items.push(req.clone());
        if self.items.len() > KEEP {
            let drop = self.items.len() - KEEP;
            self.items.drain(..drop);
        }
        Ok(req)
    }

    pub fn get(&self, id: u64) -> Option<&AccessRequest> {
        self.items.iter().find(|r| r.id == id)
    }

    pub fn list(&self) -> Vec<AccessRequest> {
        self.items.clone()
    }

    pub fn pending(&self) -> usize {
        self.items
            .iter()
            .filter(|r| r.status == RequestStatus::Pending)
            .count()
    }

    pub fn resolve(
        &mut self,
        id: u64,
        approved: bool,
        note: Option<String>,
    ) -> Result<AccessRequest, String> {
        let r = self
            .items
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| format!("no request {id}"))?;
        r.status = if approved {
            RequestStatus::Approved
        } else {
            RequestStatus::Rejected
        };
        r.resolved = Some(Utc::now());
        r.note = note;
        Ok(r.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use luoto_shared::api::Install;

    fn new(host: &str) -> NewAccessRequest {
        NewAccessRequest {
            host: host.into(),
            access: AccessLevel::Read,
            paths: vec![],
            reason: "read the docs\n\u{1b}[31m".into(),
            install: None,
        }
    }

    #[test]
    fn creates_dedups_and_limits() {
        let mut r = Requests::default();
        let a = r.create(new("Docs.rs")).unwrap();
        assert_eq!(a.host, "docs.rs");
        assert_eq!(a.reason, "read the docs[31m");
        assert_eq!(r.create(new("docs.rs")).unwrap().id, a.id);
        for i in 0..4 {
            r.create(new(&format!("h{i}.example"))).unwrap();
        }
        assert!(r.create(new("one-too-many.example")).is_err());
        assert!(r.create(new("*")).is_err());
        assert!(r.create(new("*.github.io")).is_err());
        r.resolve(a.id, true, None).unwrap();
        assert_eq!(r.pending(), 4);
    }

    #[test]
    fn install_requests_name_plain_software() {
        let mut r = Requests::default();
        let ask = |install: Install| NewAccessRequest {
            host: String::new(),
            access: AccessLevel::Read,
            paths: vec![],
            reason: "psql for the migrations".into(),
            install: Some(install),
        };
        let pkg = Install::Package {
            name: "postgresql-client".into(),
        };
        let a = r.create(ask(pkg.clone())).unwrap();
        assert_eq!(a.install.as_ref(), Some(&pkg));
        assert_eq!(r.create(ask(pkg)).unwrap().id, a.id);
        let tool = Install::Tool {
            name: "node".into(),
            version: "24".into(),
        };
        assert!(r.create(ask(tool)).is_ok());
        assert!(
            r.create(ask(Install::Preset { name: "npm".into() }))
                .is_ok()
        );
        assert!(
            r.create(ask(Install::Preset {
                name: "nope".into()
            }))
            .is_err()
        );
        for bad in [
            Install::Package {
                name: "-oDebug::x".into(),
            },
            Install::Package { name: "a b".into() },
            Install::Package {
                name: "x;rm".into(),
            },
            Install::Tool {
                name: "node".into(),
                version: "$(id)".into(),
            },
        ] {
            assert!(r.create(ask(bad)).is_err());
        }
    }
}
