use criterion::{criterion_group, criterion_main, Criterion};

fn bench_path_normalization(c: &mut Criterion) {
    c.bench_function("normalize_simple", |b| {
        b.iter(|| proxy_policy::matcher::normalize_path("/api/v1/users/123"))
    });
    c.bench_function("normalize_traversal", |b| {
        b.iter(|| proxy_policy::matcher::normalize_path("/api/v1/../../../etc/passwd"))
    });
}

fn bench_policy_evaluation(c: &mut Criterion) {
    use proxy_core::identity::{Identity, San};
    use proxy_core::policy::PolicyEngine;
    use proxy_policy::YamlPolicyEngine;

    let yaml = r#"
rules:
  - identity: "spiffe://arkion.internal/agent/*"
    allow:
      - method: GET
        path: "/api/v1/identity/**"
  - identity: "CN=admin"
    allow:
      - method: "*"
        path: "/**"
default_action: deny
"#;
    let engine = YamlPolicyEngine::from_yaml(yaml).expect("benchmark policy is valid");
    let identity = Identity {
        subject: "CN=test".to_string(),
        issuer: "CN=CA".to_string(),
        sans: vec![San::Uri("spiffe://arkion.internal/agent/42".to_string())],
        serial: "01".to_string(),
        not_before: 0,
        not_after: i64::MAX,
        chain_depth: 2,
    };

    c.bench_function("policy_allow", |b| {
        b.iter(|| engine.evaluate(&identity, "GET", "/api/v1/identity/self"))
    });
    c.bench_function("policy_deny", |b| {
        b.iter(|| engine.evaluate(&identity, "DELETE", "/admin/secret"))
    });
}

criterion_group!(benches, bench_path_normalization, bench_policy_evaluation);
criterion_main!(benches);
