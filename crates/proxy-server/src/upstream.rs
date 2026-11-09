//! Upstream request forwarding with correct proxy semantics.
//!
//! Handles method, path, query, and body forwarding. Strips hop-by-hop
//! headers and injects X-Forwarded-* headers. Body is streamed, not buffered.

use axum::body::Body;
use http::header::{
    CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
    UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

const HOP_BY_HOP: &[HeaderName] = &[
    CONNECTION,
    PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION,
    TE,
    TRAILER,
    TRANSFER_ENCODING,
    UPGRADE,
];

#[derive(Clone)]
pub struct UpstreamClient {
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Body,
    >,
    upstream_base: String,
    request_timeout: Duration,
}

impl UpstreamClient {
    pub fn new(
        upstream_url: &str,
        upstream_ca: Option<&Path>,
        request_timeout: Duration,
    ) -> Result<Self, proxy_core::ProxyError> {
        let connector = if let Some(ca_path) = upstream_ca {
            let pem = std::fs::read(ca_path).map_err(|error| {
                proxy_core::ProxyError::Config(format!(
                    "upstream CA file {}: {error}",
                    ca_path.display()
                ))
            })?;
            let roots = proxy_tls::config::load_root_store(&pem)?;
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls_config)
                .https_or_http()
                .enable_http1()
                .build()
        } else {
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|error| {
                    proxy_core::ProxyError::Config(format!(
                        "loading system roots for upstream TLS: {error}"
                    ))
                })?
                .https_or_http()
                .enable_http1()
                .build()
        };
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            client,
            upstream_base: upstream_url.trim_end_matches('/').to_string(),
            request_timeout,
        })
    }

    pub async fn forward(
        &self,
        mut req: http::Request<Body>,
        client_ip: &str,
    ) -> Result<http::Response<Body>, proxy_core::ProxyError> {
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let upstream_uri = format!("{}{}", self.upstream_base, path_and_query);
        let forwarded_host = req.headers().get(HOST).cloned().or_else(|| {
            req.uri()
                .authority()
                .and_then(|authority| HeaderValue::from_str(authority.as_str()).ok())
        });

        strip_hop_by_hop(req.headers_mut());
        inject_forwarded_headers(req.headers_mut(), client_ip, forwarded_host.as_ref());

        *req.uri_mut() = upstream_uri
            .parse()
            .map_err(|e| proxy_core::ProxyError::Upstream(format!("invalid upstream URI: {e}")))?;

        let response = tokio::time::timeout(self.request_timeout, self.client.request(req))
            .await
            .map_err(|_| proxy_core::ProxyError::Timeout(self.request_timeout.as_millis() as u64))?
            .map_err(|e| proxy_core::ProxyError::Upstream(format!("upstream failed: {e}")))?;

        let (parts, body) = response.into_parts();
        Ok(http::Response::from_parts(
            parts,
            Body::new(TimeoutBody::new(body, self.request_timeout)),
        ))
    }
}

pin_project_lite::pin_project! {
    struct TimeoutBody<B> {
        #[pin]
        inner: B,
        #[pin]
        deadline: tokio::time::Sleep,
        timed_out: bool,
    }
}

impl<B> TimeoutBody<B> {
    fn new(inner: B, timeout: Duration) -> Self {
        Self {
            inner,
            deadline: tokio::time::sleep(timeout),
            timed_out: false,
        }
    }
}

impl<B> http_body::Body for TimeoutBody<B>
where
    B: http_body::Body,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = B::Data;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if *this.timed_out {
            return std::task::Poll::Ready(None);
        }

        if this.deadline.poll(cx).is_ready() {
            *this.timed_out = true;
            return std::task::Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream response body timed out",
            )))));
        }

        match this.inner.poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => std::task::Poll::Ready(Some(Ok(frame))),
            std::task::Poll::Ready(Some(Err(error))) => {
                std::task::Poll::Ready(Some(Err(Box::new(error))))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let connection_headers: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|name| {
            let start = name
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .unwrap_or(name.len());
            let name = &name[start..];
            let end = name
                .iter()
                .rposition(|byte| !byte.is_ascii_whitespace())
                .map_or(0, |end| end + 1);
            HeaderName::from_bytes(&name[..end]).ok()
        })
        .collect();

    for header in HOP_BY_HOP {
        headers.remove(header);
    }
    headers.remove("keep-alive");
    for header in connection_headers {
        headers.remove(header);
    }
}

fn inject_forwarded_headers(
    headers: &mut HeaderMap,
    client_ip: &str,
    forwarded_host: Option<&HeaderValue>,
) {
    let set = |headers: &mut HeaderMap, name: &str, value: &str| {
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), value.parse()) {
            headers.insert(n, v);
        }
    };
    set(headers, "x-forwarded-for", client_ip);
    set(headers, "x-forwarded-proto", "https");
    if let Some(host) = forwarded_host {
        headers.insert("x-forwarded-host", host.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn strip_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "keep-alive, x-private".parse().unwrap());
        headers.insert(TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert("x-private", "must be removed".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        strip_hop_by_hop(&mut headers);
        assert!(headers.get(CONNECTION).is_none());
        assert!(headers.get(TRANSFER_ENCODING).is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("x-private").is_none());
        assert!(headers.get("content-type").is_some());
    }

    #[test]
    fn inject_forwarded() {
        let mut headers = HeaderMap::new();
        inject_forwarded_headers(
            &mut headers,
            "10.0.0.1",
            Some(&HeaderValue::from_static("proxy.example:8443")),
        );
        assert_eq!(
            headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "10.0.0.1"
        );
        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "https"
        );
        assert_eq!(
            headers.get("x-forwarded-host").unwrap().to_str().unwrap(),
            "proxy.example:8443"
        );
    }

    #[test]
    fn upstream_client_trims_trailing_slash() {
        let client =
            UpstreamClient::new("http://localhost:8080/", None, Duration::from_secs(1)).unwrap();
        assert_eq!(client.upstream_base, "http://localhost:8080");
    }

    #[tokio::test]
    async fn times_out_waiting_for_upstream_response_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let client =
            UpstreamClient::new(&format!("http://{addr}"), None, Duration::from_millis(20))
                .unwrap();
        let request = http::Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let result = client.forward(request, "127.0.0.1").await;
        assert!(matches!(result, Err(proxy_core::ProxyError::Timeout(_))));
    }

    #[tokio::test]
    async fn times_out_while_streaming_upstream_response_body() {
        use http_body::Body as _;
        use std::future::poll_fn;
        use std::pin::Pin;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = stream.write_all(b"b").await;
        });

        let client =
            UpstreamClient::new(&format!("http://{addr}"), None, Duration::from_millis(20))
                .unwrap();
        let request = http::Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let response = client.forward(request, "127.0.0.1").await.unwrap();
        let mut body = response.into_body();
        let first = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(matches!(first, Some(Ok(_))));
        let second = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(matches!(second, Some(Err(_))));
    }
}
