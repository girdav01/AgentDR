//! Tier 5 — inline blocking HTTP CONNECT proxy.
//!
//! Clients (Claude Code, Codex, browsers) point HTTP_PROXY /
//! HTTPS_PROXY at AgentDR's loopback port. For each incoming CONNECT
//! the proxy synthesises a "candidate" EventRecord (ai_operation=inference,
//! API Activity 6003, if the host matches a known AI endpoint, else
//! ai_operation=agent_action) and feeds it to the PolicyEngine. If any
//! matching policy returns Action::Block, the proxy responds `403 Forbidden`
//! and emits a Compliance Finding (OCSF 2003) event. Otherwise it tunnels
//! the TCP bytes through and emits the observation event.
//!
//! No TLS MITM is performed: CONNECT carries the hostname in plaintext,
//! which is sufficient for endpoint-allowlist enforcement without
//! shipping a custom CA.

use crate::models::*;
use crate::policy::{Action, PolicyEngine};
use serde_json::json;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

pub struct InlineProxy {
    bind: String,
    engine: Arc<PolicyEngine>,
    /// Hostname allow-list (case-insensitive substring). When non-empty
    /// and the destination host doesn't match any entry, the proxy
    /// short-circuits with a deny before even consulting policies.
    allowlist: Vec<String>,
    tx: mpsc::UnboundedSender<EventRecord>,
}

impl InlineProxy {
    pub fn new(
        bind: String,
        engine: Arc<PolicyEngine>,
        allowlist: Vec<String>,
        tx: mpsc::UnboundedSender<EventRecord>,
    ) -> Self {
        Self { bind, engine, allowlist, tx }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let listener = match TcpListener::bind(&self.bind).await {
            Ok(l) => l,
            Err(e) => { error!("proxy bind {}: {e}", self.bind); return; }
        };
        info!("inline proxy listening on http://{} (policy mode)", self.bind);

        let me = Arc::new(self);
        loop {
            tokio::select! {
                accept = listener.accept() => match accept {
                    Ok((sock, _addr)) => {
                        let me = me.clone();
                        tokio::spawn(async move { me.handle(sock).await; });
                    }
                    Err(e) => warn!("proxy accept: {e}"),
                },
                _ = shutdown.changed() => break,
            }
        }
        info!("inline proxy shutting down");
    }

    async fn handle(self: Arc<Self>, mut client: TcpStream) {
        // Read just enough to get the request line + headers.
        let mut buf = vec![0u8; 8192];
        let n = match client.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        let head = String::from_utf8_lossy(&buf[..n]).to_string();

        let Some((method, target)) = parse_method_target(&head) else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return;
        };

        // Resolve the destination host[:port]. CONNECT carries it in the
        // target; plain HTTP requests carry an absolute URI we need to
        // tease apart.
        let (host, port) = match method.as_str() {
            "CONNECT" => split_host_port(&target, 443),
            _ => match host_port_from_url(&target) {
                Some(hp) => hp,
                None => match host_from_headers(&head) {
                    Some(h) => split_host_port(&h, 80),
                    None => {
                        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                        return;
                    }
                },
            },
        };

        // Run policy check.
        let probe = self.probe_event(&method, &host, port);
        let decision = self.engine.evaluate(&probe);
        let denied_by_allowlist = !self.allowlist.is_empty()
            && !self.allowlist.iter().any(|a| host.to_lowercase().contains(&a.to_lowercase()));

        let blocked = decision.action == Action::Block || denied_by_allowlist;

        // Emit any policy events.
        for ev in decision.events { let _ = self.tx.send(ev); }

        if blocked {
            // 403 + emit a Compliance Finding (OCSF 2003) record if the
            // allowlist (not policy) was the reason, so the trace is complete.
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nProxy-Agent: AgentDR\r\nContent-Length: 0\r\n\r\n").await;
            if denied_by_allowlist {
                let mut ev = self.probe_event(&method, &host, port);
                ev.event_type = "proxy_block".into();
                ev.set_op(AiOperation::ComplianceViolation, ACTIVITY_BLOCK);
                ev.activity_id = Some(ACTIVITY_BLOCK);
                ev.status_id = Some(STATUS_BLOCKED);
                ev.risk_level = "high".into();
                ev.severity_id = Some(4);
                ev.message = Some(format!("proxy: denied {} {}:{} (host not in allowlist)", method, host, port));
                ev.source = Some("proxy".into());
                let _ = self.tx.send(ev);
            }
            return;
        }

        // Allow path: also emit an observation so SIEM sees who talked to whom.
        let mut obs = self.probe_event(&method, &host, port);
        obs.event_type = "proxy_allow".into();
        obs.message = Some(format!("proxy: allowed {} {}:{}", method, host, port));
        obs.source = Some("proxy".into());
        let _ = self.tx.send(obs);

        // Now actually proxy.
        if method == "CONNECT" {
            self.tunnel_connect(client, &host, port).await;
        } else {
            self.tunnel_http(client, head.as_bytes(), &host, port).await;
        }
    }

    fn probe_event(&self, method: &str, host: &str, port: u16) -> EventRecord {
        let ai = classify_ai_endpoint(host);
        let messaging = classify_messaging_endpoint(host);
        let op = if ai.is_some() {
            AiOperation::Inference
        } else if messaging.is_some() {
            AiOperation::PermissionEscalation
        } else {
            AiOperation::AgentAction
        };
        let risk = if ai.is_some() { "medium" } else if messaging.is_some() { "high" } else { "low" };

        let mut ev = EventRecord::new("proxy_request", json!({
            "method": method,
            "host":   host,
            "port":   port,
            "ai_provider": ai.as_ref().map(|p| &p.provider),
            "messaging":   messaging,
        }), risk);
        ev.set_op(op, ACTIVITY_EXECUTE);
        ev.activity_id = Some(ACTIVITY_EXECUTE);
        ev.status_id = Some(STATUS_SUCCESS);
        if let Some(a) = ai {
            ev.provider = Some(a.provider);
            ev.model    = Some(a.model);
        }
        ev
    }

    async fn tunnel_connect(self: Arc<Self>, mut client: TcpStream, host: &str, port: u16) {
        let upstream = match TcpStream::connect((host, port)).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client.write_all(format!("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").as_bytes()).await;
                debug!("proxy upstream connect {}:{}: {e}", host, port);
                return;
            }
        };
        if client.write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: AgentDR\r\n\r\n").await.is_err() {
            return;
        }
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        let a = tokio::io::copy(&mut cr, &mut uw);
        let b = tokio::io::copy(&mut ur, &mut cw);
        let _ = tokio::join!(a, b);
    }

    async fn tunnel_http(self: Arc<Self>, mut client: TcpStream, initial: &[u8], host: &str, port: u16) {
        let mut upstream = match TcpStream::connect((host, port)).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                debug!("proxy upstream connect {}:{}: {e}", host, port);
                return;
            }
        };
        if upstream.write_all(initial).await.is_err() { return; }
        let (mut cr, mut cw) = client.into_split();
        let (mut ur, mut uw) = upstream.into_split();
        let a = tokio::io::copy(&mut cr, &mut uw);
        let b = tokio::io::copy(&mut ur, &mut cw);
        let _ = tokio::join!(a, b);
    }
}

fn parse_method_target(head: &str) -> Option<(String, String)> {
    let first = head.lines().next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    Some((method, target))
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (s.to_string(), default_port)
}

fn host_port_from_url(target: &str) -> Option<(String, u16)> {
    // Strip scheme://, take everything up to the first '/'
    let rest = target.split_once("://").map(|x| x.1).unwrap_or(target);
    let authority = rest.split_once('/').map(|x| x.0).unwrap_or(rest);
    if authority.is_empty() { return None; }
    let default = if target.starts_with("https://") { 443 } else { 80 };
    Some(split_host_port(authority, default))
}

fn host_from_headers(head: &str) -> Option<String> {
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}
