use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, Response, StatusCode},
    routing::{any, get},
};
use futures_util::StreamExt;
use serde::Deserialize;
use std::{
    collections::HashMap,
    env, fs,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;
const MIN_TOKEN_LENGTH: usize = 32;

#[derive(Debug, Deserialize)]
struct ApiPermission {
    client: String,
    path: String,
    method: String,
}

#[derive(Debug, Deserialize)]
struct Policy {
    permissions: Vec<ApiPermission>,
}

#[derive(Debug, Deserialize)]
struct GatewayConfig {
    upstream_base_url: String,
    policy_file: String,
}

#[derive(Clone)]
struct AppState {
    policy: Arc<Policy>,
    // Tokens are loaded from server environment variables and never logged.
    clients_by_token: Arc<HashMap<String, String>>,
    upstream_base_url: reqwest::Url,
    http_client: reqwest::Client,
}

fn response(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(message.into()))
        .expect("static response is valid")
}

fn is_safe_api_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains("//")
        && !path.contains('%')
        && !path.contains('\\')
        && !path.contains('?')
        && !path.contains('#')
        && path.is_ascii()
        && !path
            .chars()
            .any(|character| character.is_ascii_control() || character == ' ')
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

fn validate_policy(policy: &Policy) -> Result<(), String> {
    if policy.permissions.is_empty() {
        return Err("policy must contain at least one permission".to_owned());
    }

    for (index, permission) in policy.permissions.iter().enumerate() {
        if permission.client.trim().is_empty() {
            return Err(format!("permission {} has an empty client name", index + 1));
        }
        if !is_safe_api_path(&permission.path) {
            return Err(format!(
                "permission {} has an unsafe path: {:?}",
                index + 1,
                permission.path
            ));
        }
        if !matches!(
            permission.method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        ) {
            return Err(format!(
                "permission {} has an unsupported method: {:?}",
                index + 1,
                permission.method
            ));
        }
    }

    Ok(())
}

fn parse_upstream_base_url(raw: &str) -> Result<reqwest::Url, String> {
    let url =
        reqwest::Url::parse(raw).map_err(|error| format!("invalid upstream_base_url: {error}"))?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err("upstream URL must use HTTP or HTTPS".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("upstream URL must not contain embedded credentials".to_owned());
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(
            "upstream_base_url must contain only scheme, host, and optional port".to_owned(),
        );
    }
    let host = url.host_str().unwrap_or_default();
    let is_loopback_host =
        host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1";
    if url.scheme() == "http" && !is_loopback_host {
        return Err(
            "plain HTTP is allowed only for loopback development; use HTTPS for remote upstreams"
                .to_owned(),
        );
    }

    Ok(url)
}

fn load_token(
    env_name: &str,
    client_name: &str,
    clients_by_token: &mut HashMap<String, String>,
) -> Result<(), String> {
    let token = env::var(env_name)
        .map_err(|_| format!("required environment variable {env_name} is not set"))?;

    if token.len() < MIN_TOKEN_LENGTH {
        return Err(format!(
            "token in {env_name} must be at least {MIN_TOKEN_LENGTH} bytes"
        ));
    }
    if !token.is_ascii() || token.chars().any(char::is_whitespace) {
        return Err(format!(
            "token in {env_name} must be ASCII without whitespace"
        ));
    }
    if clients_by_token.contains_key(&token) {
        return Err("each client must have a unique token".to_owned());
    }

    clients_by_token.insert(token, client_name.to_owned());
    Ok(())
}

async fn proxy_handler(State(state): State<AppState>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();

    // 1. Authenticate. The request never chooses its own client identity.
    let authorization = parts
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());

    let supplied_token = authorization.and_then(|value| {
        let (scheme, token) = value.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty() {
            Some(token)
        } else {
            None
        }
    });

    let client_name = match supplied_token.and_then(|token| state.clients_by_token.get(token)) {
        Some(client) => client,
        None => return response(StatusCode::UNAUTHORIZED, "Unauthorized"),
    };

    // 2. Derive the API path from the gateway route and reject ambiguous forms.
    let Some(api_path) = parts.uri.path().strip_prefix("/proxy") else {
        return response(StatusCode::NOT_FOUND, "Unknown gateway route");
    };

    if !is_safe_api_path(api_path) {
        return response(StatusCode::BAD_REQUEST, "Unsafe or ambiguous API path");
    }

    let method = parts.method.as_str();

    // 3. Exact match: authenticated identity + HTTP method + normalized-safe path.
    let permitted = state.policy.permissions.iter().any(|permission| {
        permission.client.as_str() == client_name.as_str()
            && permission.method == method
            && permission.path == api_path
    });

    if !permitted {
        println!(
            "[DENY] client={} method={} path={}",
            client_name, method, api_path
        );
        return response(StatusCode::FORBIDDEN, "Blocked by SENTINEL-API policy");
    }

    // 4. Enforce request-body limit before forwarding.
    let body_bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body exceeds the 2 MiB limit",
            );
        }
    };

    // 5. The upstream comes only from owner configuration, never caller input.
    // Build the target from a parsed base URL instead of concatenating a raw URL.
    let mut upstream_url = state.upstream_base_url.clone();
    upstream_url.set_path(api_path);
    upstream_url.set_query(parts.uri.query());

    let mut outgoing = state
        .http_client
        .request(parts.method.clone(), upstream_url)
        .body(body_bytes);

    // Forward only the request content type. Do not forward client credentials,
    // Host, cookies, forwarding headers, or other caller-controlled headers.
    if let Some(content_type) = parts.headers.get("content-type") {
        outgoing = outgoing.header("content-type", content_type);
    }

    println!(
        "[ALLOW] client={} method={} path={}",
        client_name, method, api_path
    );

    let upstream = match outgoing.send().await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("[UPSTREAM ERROR] request failed: {error}");
            return response(StatusCode::BAD_GATEWAY, "Upstream request failed");
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();

    // Bound upstream responses too; chunked responses cannot bypass this limit.
    let mut stream = upstream.bytes_stream();
    let mut response_bytes = Vec::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(chunk) => chunk,
            Err(_) => return response(StatusCode::BAD_GATEWAY, "Could not read upstream response"),
        };

        if response_bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY_BYTES {
            return response(
                StatusCode::BAD_GATEWAY,
                "Upstream response exceeds the 4 MiB limit",
            );
        }

        response_bytes.extend_from_slice(&chunk);
    }

    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Body::from(response_bytes))
        .expect("validated upstream status and content type produce a valid response")
}

// Local-only mock upstream for deterministic portfolio demos.
async fn mock_status(State(hits): State<Arc<AtomicUsize>>) -> axum::Json<serde_json::Value> {
    let count = hits.fetch_add(1, Ordering::SeqCst) + 1;
    println!("[MOCK UPSTREAM] GET /v1/status reached (request #{count})");
    axum::Json(serde_json::json!({"status": "healthy", "service": "mock-api"}))
}

async fn mock_users(State(hits): State<Arc<AtomicUsize>>) -> axum::Json<serde_json::Value> {
    let count = hits.fetch_add(1, Ordering::SeqCst) + 1;
    println!("[MOCK UPSTREAM] GET /v1/users reached (request #{count})");
    axum::Json(serde_json::json!({"users": ["demo-user"]}))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_text = fs::read_to_string("gateway.toml")?;
    let config: GatewayConfig = toml::from_str(&config_text)?;
    let upstream_base_url = parse_upstream_base_url(&config.upstream_base_url)
        .unwrap_or_else(|error| panic!("Invalid upstream configuration: {error}"));

    let policy_text = fs::read_to_string(&config.policy_file)?;
    let policy: Policy = toml::from_str(&policy_text)?;
    validate_policy(&policy)
        .unwrap_or_else(|error| panic!("Invalid policy configuration: {error}"));

    let mut clients_by_token = HashMap::new();
    load_token("SENTINEL_DEMO_APP_TOKEN", "demo-app", &mut clients_by_token)
        .unwrap_or_else(|error| panic!("Invalid demo-app token: {error}"));
    load_token(
        "SENTINEL_BILLING_APP_TOKEN",
        "billing-app",
        &mut clients_by_token,
    )
    .unwrap_or_else(|error| panic!("Invalid billing-app token: {error}"));

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()?;

    // Start the mock only for the repository's local demo destination.
    // For other owner-configured HTTPS upstreams, no mock listener is opened.
    if upstream_base_url.scheme() == "http"
        && upstream_base_url.host_str() == Some("127.0.0.1")
        && upstream_base_url.port_or_known_default() == Some(9001)
    {
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:9001").await?;
        let mock_app = Router::new()
            .route("/v1/status", get(mock_status))
            .route("/v1/users", get(mock_users))
            .with_state(upstream_hits);

        tokio::spawn(async move {
            println!("[MOCK UPSTREAM] Listening on 127.0.0.1:9001 (local demo only)");
            if let Err(error) = axum::serve(mock_listener, mock_app).await {
                eprintln!("[MOCK SERVER ERROR] {error}");
            }
        });
    }

    let state = AppState {
        policy: Arc::new(policy),
        clients_by_token: Arc::new(clients_by_token),
        upstream_base_url,
        http_client,
    };

    let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    let address: SocketAddr = gateway_listener.local_addr()?;
    let gateway_app = Router::new()
        .route("/proxy/{*path}", any(proxy_handler))
        .with_state(state);

    println!("[SENTINEL-API] Listening on http://{address}");
    axum::serve(gateway_listener, gateway_app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn counted_upstream(
        State(hits): State<Arc<AtomicUsize>>,
    ) -> axum::Json<serde_json::Value> {
        hits.fetch_add(1, Ordering::SeqCst);
        axum::Json(serde_json::json!({"result": "reached-upstream"}))
    }

    #[tokio::test]
    async fn authz_isolation_and_upstream_boundary_are_enforced() {
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let mock_app = Router::new()
            .route("/v1/status", any(counted_upstream))
            .route("/v1/users", any(counted_upstream))
            .with_state(upstream_hits.clone());

        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test upstream");
        let mock_address = mock_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(mock_listener, mock_app)
                .await
                .expect("test upstream server");
        });

        let demo_token = "test-demo-token-for-unit-tests-2026";
        let billing_token = "test-billing-token-for-unit-tests-2026";
        let clients_by_token = HashMap::from([
            (demo_token.to_owned(), "demo-app".to_owned()),
            (billing_token.to_owned(), "billing-app".to_owned()),
        ]);
        let policy = Policy {
            permissions: vec![
                ApiPermission {
                    client: "demo-app".to_owned(),
                    path: "/v1/status".to_owned(),
                    method: "GET".to_owned(),
                },
                ApiPermission {
                    client: "billing-app".to_owned(),
                    path: "/v1/users".to_owned(),
                    method: "GET".to_owned(),
                },
            ],
        };
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let state = AppState {
            policy: Arc::new(policy),
            clients_by_token: Arc::new(clients_by_token),
            upstream_base_url: reqwest::Url::parse(&format!("http://{mock_address}")).unwrap(),
            http_client,
        };

        let gateway_app = Router::new()
            .route("/proxy/{*path}", any(proxy_handler))
            .with_state(state);
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test gateway");
        let gateway_address = gateway_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(gateway_listener, gateway_app)
                .await
                .expect("test gateway server");
        });

        let client = reqwest::Client::new();
        let gateway_url = format!("http://{gateway_address}");

        // Allowed request passes through.
        let result = client
            .get(format!("{gateway_url}/proxy/v1/status"))
            .bearer_auth(demo_token)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        // Cross-client access is denied without touching the upstream.
        let result = client
            .get(format!("{gateway_url}/proxy/v1/users"))
            .bearer_auth(demo_token)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        let result = client
            .get(format!("{gateway_url}/proxy/v1/status"))
            .bearer_auth(billing_token)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        // Wrong method, missing token, invalid token, and unknown route all fail closed.
        let result = client
            .post(format!("{gateway_url}/proxy/v1/users"))
            .bearer_auth(demo_token)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        let result = client
            .get(format!("{gateway_url}/proxy/v1/status"))
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        let result = client
            .get(format!("{gateway_url}/proxy/v1/status"))
            .bearer_auth("definitely-not-a-valid-token")
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        let result = client
            .get(format!("{gateway_url}/proxy/v1/admin"))
            .bearer_auth(demo_token)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        // Percent-encoded paths are rejected to avoid ambiguous normalization.
        let result = client
            .get(format!("{gateway_url}/proxy/v1/%2Fstatus"))
            .bearer_auth(demo_token)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

        // billing-app's explicitly permitted route passes through.
        let result = client
            .get(format!("{gateway_url}/proxy/v1/users"))
            .bearer_auth(billing_token)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn path_validation_rejects_ambiguous_forms() {
        assert!(is_safe_api_path("/v1/status"));
        assert!(!is_safe_api_path("/v1/%2e%2e/admin"));
        assert!(!is_safe_api_path("/v1/../admin"));
        assert!(!is_safe_api_path("//v1/status"));
        assert!(!is_safe_api_path("/v1\\status"));
    }

    #[test]
    fn upstream_validation_requires_safe_base_url() {
        assert!(parse_upstream_base_url("http://127.0.0.1:9001").is_ok());
        assert!(parse_upstream_base_url("https://api.example.com").is_ok());
        assert!(parse_upstream_base_url("http://api.example.com").is_err());
        assert!(parse_upstream_base_url("http://user:password@127.0.0.1:9001").is_err());
        assert!(parse_upstream_base_url("http://127.0.0.1:9001/base?x=1").is_err());
    }
}
