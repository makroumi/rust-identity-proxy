//! Identity-aware TLS reverse proxy binary.
//!
//! Usage: `identity-proxy --config config/proxy.toml`

use anyhow::Context;
use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use clap::Parser;
use http::StatusCode;
use proxy_core::identity::Identity;
use proxy_core::policy::{PolicyDecision, PolicyEngine};
use proxy_policy::YamlPolicyEngine;
use proxy_server::audit_layer::AuditLayer;
use proxy_server::config::ProxyConfig;
use proxy_server::limits::RateLimiter;
use proxy_server::upstream::UpstreamClient;
use proxy_tls::config::{load_private_key, load_server_certs};
use proxy_trust::HotReloadTrustStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::{ServiceBuilder, ServiceExt};
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::EnvFilter;

const HEALTH_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

#[derive(Parser)]
#[command(name = "identity-proxy", about = "Identity-aware TLS reverse proxy")]
struct Args {
    #[arg(short, long, default_value = "config/proxy.toml")]
    config: PathBuf,
    #[arg(long)]
    healthcheck: bool,
}

#[derive(Clone)]
struct AppState {
    upstream: UpstreamClient,
    policy: Arc<YamlPolicyEngine>,
    request_slots: Arc<tokio::sync::Semaphore>,
    rate_limiter: Arc<RateLimiter>,
}

struct TlsRuntime {
    acceptor: Arc<ArcSwap<TlsAcceptor>>,
    trust_store: Arc<HotReloadTrustStore>,
    server_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = ProxyConfig::from_file(&args.config).context("loading config")?;
    if args.healthcheck {
        return healthcheck(&config.server.health_addr).await;
    }

    tracing::info!(
        listen = %config.server.listen_addr,
        upstream = %config.server.upstream_url,
        "starting identity-aware proxy"
    );

    let srv_cert_pem = std::fs::read(&config.tls.server_cert).context("server cert")?;
    let srv_key_pem = std::fs::read(&config.tls.server_key).context("server key")?;
    let trust_store =
        Arc::new(HotReloadTrustStore::new(&config.trust.ca_bundle_path).context("trust store")?);
    let server_certs = load_server_certs(&srv_cert_pem)?;
    let server_key = load_private_key(&srv_key_pem)?;
    let tls_config = proxy_tls::build_server_config(
        server_certs.clone(),
        server_key.clone_key(),
        (*trust_store.current_store()).clone(),
    )?;
    let tls_runtime = TlsRuntime {
        acceptor: Arc::new(ArcSwap::from(Arc::new(TlsAcceptor::from(Arc::new(
            tls_config,
        ))))),
        trust_store,
        server_certs,
        server_key,
    };
    let policy =
        Arc::new(YamlPolicyEngine::from_file(&config.policy.policy_file).context("policy")?);
    let upstream = UpstreamClient::new(
        &config.server.upstream_url,
        config.tls.upstream_ca.as_deref(),
        Duration::from_secs(config.limits.request_timeout_secs),
    )?;

    let state = AppState {
        upstream,
        policy,
        request_slots: Arc::new(tokio::sync::Semaphore::new(config.limits.max_concurrency)),
        rate_limiter: Arc::new(RateLimiter::new(
            config.limits.rate_limit_rps,
            config.limits.rate_limit_burst,
        )),
    };

    let app = Router::new()
        .route("/health", get(|| async { (StatusCode::OK, "ok") }))
        .route("/ready", get(|| async { (StatusCode::OK, "ready") }))
        .fallback(proxy_handler)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_request_limits,
        ))
        .layer(
            ServiceBuilder::new()
                .layer(AuditLayer)
                .layer(RequestBodyLimitLayer::new(config.limits.max_body_bytes)),
        )
        .with_state(state);

    let addr: SocketAddr = config.server.listen_addr.parse().context("listen addr")?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "proxy listening with mTLS");
    let health_listener = TcpListener::bind(&config.server.health_addr)
        .await
        .context("binding loopback health listener")?;

    serve_loop(
        listener,
        health_listener,
        app,
        tls_runtime,
        config.limits.max_connections,
    )
    .await
    .context("serving proxy")?;
    tracing::info!("proxy shut down cleanly");
    Ok(())
}

async fn healthcheck(health_addr: &str) -> anyhow::Result<()> {
    let addr: SocketAddr = health_addr.parse().context("parsing healthcheck address")?;
    let response = tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to health listener at {addr}"))?;
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;
        let mut response = [0; 128];
        let read = stream.read(&mut response).await?;
        Ok::<_, anyhow::Error>(response[..read].starts_with(b"HTTP/1.1 200 OK\r\n"))
    })
    .await
    .context("healthcheck timed out")??;
    if !response {
        anyhow::bail!("health listener returned an unhealthy response");
    }
    Ok(())
}

async fn serve_loop(
    listener: TcpListener,
    health_listener: TcpListener,
    app: Router,
    tls_runtime: TlsRuntime,
    max_connections: usize,
) -> anyhow::Result<()> {
    let TlsRuntime {
        acceptor,
        trust_store,
        server_certs,
        server_key,
    } = tls_runtime;
    let connection_slots = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let mut connections = JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    #[cfg(unix)]
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel(1);
    #[cfg(not(unix))]
    let (_reload_tx, mut reload_rx) = tokio::sync::mpsc::channel(1);
    #[cfg(unix)]
    let reload_task = {
        use tokio::signal::unix::{signal, SignalKind};
        let mut reload = signal(SignalKind::hangup()).context("registering SIGHUP handler")?;
        tokio::spawn(async move {
            while reload.recv().await.is_some() {
                if reload_tx.try_send(()).is_err() {
                    tracing::warn!("trust reload already pending; coalescing SIGHUP");
                }
            }
        })
    };

    loop {
        tokio::select! {
            accepted = health_listener.accept() => {
                let (mut stream, remote_addr) = accepted.context("accepting healthcheck connection")?;
                match tokio::time::timeout(Duration::from_secs(1), stream.write_all(HEALTH_RESPONSE)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::debug!(%remote_addr, %error, "healthcheck connection failed"),
                    Err(_) => tracing::warn!(%remote_addr, "healthcheck response timed out"),
                }
            }
            accepted = listener.accept() => {
                let (stream, remote_addr) = accepted.context("accepting client connection")?;
                let connection_slot = match connection_slots.clone().try_acquire_owned() {
                    Ok(slot) => slot,
                    Err(_) => {
                        tracing::warn!(%remote_addr, "connection limit reached; dropping connection");
                        drop(stream);
                        continue;
                    }
                };
                let acceptor = acceptor.load_full();
                let app = app.clone();

                connections.spawn(async move {
                    let _connection_slot = connection_slot;
                    let tls_stream = match tokio::time::timeout(
                        Duration::from_secs(10),
                        acceptor.accept(stream),
                    ).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(error)) => {
                            tracing::warn!(%remote_addr, error = %error, "TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(%remote_addr, "TLS handshake timed out");
                            return;
                        }
                    };

                    let (_, conn) = tls_stream.get_ref();
                    let identity = conn
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .and_then(|cert| match proxy_tls::extract_identity(cert.as_ref()) {
                            Ok(identity) => Some(identity),
                            Err(error) => {
                                tracing::warn!(error = %error, "client certificate identity extraction failed");
                                None
                            }
                        });

                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let svc = hyper::service::service_fn(
                        move |req: http::Request<hyper::body::Incoming>| {
                            let app = app.clone();
                            let identity = identity.clone();
                            async move {
                                let (mut parts, body) = req.into_parts();
                                parts.extensions.insert(remote_addr);
                                if let Some(id) = identity {
                                    parts.extensions.insert(id);
                                }
                                let req = http::Request::from_parts(parts, Body::new(body));
                                let resp = app.oneshot(req).await.unwrap_or_else(|e| match e {});
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        },
                    );

                    let mut http1 = hyper::server::conn::http1::Builder::new();
                    http1.timer(hyper_util::rt::TokioTimer::new());
                    http1.header_read_timeout(Duration::from_secs(10));
                    if let Err(error) = http1.serve_connection(io, svc).await {
                        tracing::debug!(%remote_addr, error = %error, "HTTP connection closed");
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::error!(error = %error, "connection task failed");
                }
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received; draining connections");
                break;
            }
            Some(()) = reload_rx.recv() => {
                match trust_store.reload() {
                    Ok(()) => {
                        match proxy_tls::build_server_config(
                            server_certs.clone(),
                            server_key.clone_key(),
                            (*trust_store.current_store()).clone(),
                        ) {
                            Ok(config) => {
                                acceptor.store(Arc::new(TlsAcceptor::from(Arc::new(config))));
                                tracing::info!("client CA trust reloaded for new TLS handshakes");
                            }
                            Err(error) => {
                                tracing::error!(%error, "failed to rebuild TLS acceptor; retaining previous acceptor");
                            }
                        }
                    }
                    Err(error) => tracing::error!(%error, "client CA trust reload failed"),
                }
            }
        }
    }

    #[cfg(unix)]
    reload_task.abort();

    let drain = async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::error!(%error, "connection task failed during shutdown");
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(30), drain)
        .await
        .is_err()
    {
        tracing::warn!("connection drain timed out; aborting remaining connections");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate =
            signal(SignalKind::terminate()).context("registering SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C")?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    Ok(())
}

async fn enforce_request_limits(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !state.rate_limiter.try_acquire() {
        return (StatusCode::TOO_MANY_REQUESTS, "request rate limit exceeded").into_response();
    }

    let _permit = match state.request_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "request concurrency limit reached",
            )
                .into_response();
        }
    };
    next.run(request).await
}

async fn proxy_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut req: axum::extract::Request,
) -> Response {
    let remote_addr = match req.extensions().get::<SocketAddr>() {
        Some(addr) => *addr,
        None => {
            tracing::error!("request is missing its accepted peer address");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "request context unavailable",
            )
                .into_response();
        }
    };

    let identity = match req.extensions().get::<Identity>().cloned() {
        Some(id) => id,
        None => {
            tracing::warn!("request without client identity, denying");
            return with_policy_decision(
                (StatusCode::UNAUTHORIZED, "client certificate required").into_response(),
                PolicyDecision::Deny("client certificate required".to_string()),
            );
        }
    };

    let normalized_path = proxy_policy::matcher::normalize_path(req.uri().path());
    if normalized_path != req.uri().path() {
        let path_and_query = match req.uri().query() {
            Some(query) => format!("{normalized_path}?{query}"),
            None => normalized_path.clone(),
        };
        match path_and_query.parse() {
            Ok(uri) => *req.uri_mut() = uri,
            Err(error) => {
                tracing::warn!(%error, "normalized request path is invalid");
                return (StatusCode::BAD_REQUEST, "invalid request path").into_response();
            }
        }
    }

    let decision = state
        .policy
        .evaluate(&identity, req.method().as_str(), &normalized_path);
    let client_ip = remote_addr.ip().to_string();

    match decision {
        PolicyDecision::Allow => match state.upstream.forward(req, &client_ip).await {
            Ok(resp) => with_policy_decision(resp.into_response(), PolicyDecision::Allow),
            Err(e) => {
                let status = match &e {
                    proxy_core::ProxyError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
                    _ => StatusCode::BAD_GATEWAY,
                };
                tracing::error!(error = %e, "upstream forwarding failed");
                with_policy_decision(
                    (status, "upstream error").into_response(),
                    PolicyDecision::Allow,
                )
            }
        },
        PolicyDecision::Deny(reason) => {
            tracing::warn!(reason = %reason, "policy denied request");
            with_policy_decision(
                (StatusCode::FORBIDDEN, reason.clone()).into_response(),
                PolicyDecision::Deny(reason),
            )
        }
    }
}

fn with_policy_decision(mut response: Response, decision: PolicyDecision) -> Response {
    response.extensions_mut().insert(decision);
    response
}
