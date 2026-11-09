//! Tower middleware layer for structured audit logging.
//!
//! Wraps every request to produce an `AuditEvent` with timing, identity,
//! policy decision, and upstream status. Sensitive headers are never logged.

use axum::extract::Request;
use pin_project_lite::pin_project;
use proxy_core::audit::AuditEvent;
use proxy_core::identity::Identity;
use proxy_core::policy::PolicyDecision;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tower::{Layer, Service};

const SAFE_HEADER_NAMES: &[&str] = &[
    "content-type",
    "content-length",
    "accept",
    "user-agent",
    "x-request-id",
];

#[derive(Clone)]
pub struct AuditLayer;

impl<S> Layer<S> for AuditLayer {
    type Service = AuditService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AuditService { inner }
    }
}

#[derive(Clone)]
pub struct AuditService<S> {
    inner: S,
}

impl<S, B> Service<Request> for AuditService<S>
where
    S: Service<Request, Response = http::Response<B>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = AuditFuture<S::Future, B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let start = Instant::now();
        let method = req.method().to_string();
        let path = req.uri().path().to_string();
        let identity = req.extensions().get::<Identity>().cloned();
        let decision = req
            .extensions()
            .get::<PolicyDecision>()
            .cloned()
            .unwrap_or(PolicyDecision::Allow);
        let request_id = uuid::Uuid::new_v4().to_string();

        AuditFuture {
            inner: self.inner.call(req),
            start,
            method,
            path,
            identity,
            decision,
            request_id,
            _body: PhantomData,
        }
    }
}

pin_project! {
    pub struct AuditFuture<F, B> {
        #[pin]
        inner: F,
        start: Instant,
        method: String,
        path: String,
        identity: Option<Identity>,
        decision: PolicyDecision,
        request_id: String,
        _body: PhantomData<fn() -> B>,
    }
}

impl<F, B, E> Future for AuditFuture<F, B>
where
    F: Future<Output = Result<http::Response<B>, E>>,
{
    type Output = Result<http::Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Ready(result) => {
                let latency_ms = this.start.elapsed().as_millis() as u64;
                let decision = result
                    .as_ref()
                    .ok()
                    .and_then(|response| response.extensions().get::<PolicyDecision>())
                    .cloned()
                    .unwrap_or_else(|| this.decision.clone());
                let upstream_status = match &result {
                    Ok(resp) => Some(resp.status().as_u16()),
                    Err(_) => None,
                };
                let event = AuditEvent {
                    request_id: this.request_id.clone(),
                    identity: this.identity.as_ref().map(|id| id.into()),
                    method: this.method.clone(),
                    path: this.path.clone(),
                    decision,
                    upstream_status,
                    latency_ms,
                    timestamp: format!(
                        "{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    ),
                };
                match serde_json::to_string(&event) {
                    Ok(json) => tracing::info!(audit = %json, "request completed"),
                    Err(error) => tracing::error!(
                        request_id = %event.request_id,
                        error = %error,
                        "failed to serialize audit event"
                    ),
                }
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[allow(dead_code)]
pub fn is_safe_header(name: &str) -> bool {
    SAFE_HEADER_NAMES.contains(&name.to_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_header_check() {
        assert!(is_safe_header("content-type"));
        assert!(is_safe_header("Content-Type"));
        assert!(!is_safe_header("authorization"));
        assert!(!is_safe_header("cookie"));
        assert!(!is_safe_header("x-api-key"));
    }
}
