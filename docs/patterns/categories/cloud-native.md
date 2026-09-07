# cloud-native patterns

Cloud-native build and runtime practices

**38 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`api-gateway`](#api-gateway) | low | high | API Gateway detected |
| [`aws-ecs-task`](#aws-ecs-task) | low | high | AWS ECS task definition detected |
| [`aws-eks-cluster`](#aws-eks-cluster) | low | high | AWS EKS cluster detected |
| [`aws-lambda-function`](#aws-lambda-function) | low | medium | AWS Lambda function reference detected |
| [`aws-sam-template`](#aws-sam-template) | low | high | AWS SAM template detected |
| [`azure-aks-cluster`](#azure-aks-cluster) | low | high | Azure AKS cluster detected |
| [`azure-functions`](#azure-functions) | low | high | Azure Functions detected |
| [`circuit-breaker`](#circuit-breaker) | medium | high | Circuit breaker pattern detected |
| [`cloud-native-kubernetes-secret`](#cloud-native-kubernetes-secret) | high | high | Kubernetes Secret resource detected |
| [`cloud-native-kubernetes-service`](#cloud-native-kubernetes-service) | low | high | Kubernetes Service detected |
| [`consul-service`](#consul-service) | low | medium | Consul service definition detected |
| [`container-capabilities`](#container-capabilities) | high | high | Dangerous container capability added |
| [`container-liveness-probe`](#container-liveness-probe) | medium | high | Container liveness probe configured |
| [`container-privileged`](#container-privileged) | critical | high | Privileged container detected |
| [`container-readiness-probe`](#container-readiness-probe) | medium | high | Container readiness probe configured |
| [`container-resources`](#container-resources) | low | high | Container resource limits configured |
| [`container-security-context`](#container-security-context) | medium | high | Container security context configured |
| [`dockerfile-exposed`](#dockerfile-exposed) | medium | high | Potentially sensitive port exposed in Dockerfile |
| [`elasticsearch-config`](#elasticsearch-config) | low | high | Elasticsearch configuration detected |
| [`etcd-service`](#etcd-service) | low | medium | etcd service configuration detected |
| [`fluentd-config`](#fluentd-config) | low | high | Fluentd logging configuration detected |
| [`gcp-gke-cluster`](#gcp-gke-cluster) | low | high | GCP GKE cluster detected |
| [`google-cloud-function`](#google-cloud-function) | low | high | Google Cloud Function detected |
| [`grafana-dashboard`](#grafana-dashboard) | low | high | Grafana dashboard detected |
| [`helm-release`](#helm-release) | low | high | Helm release detected |
| [`helm-repo`](#helm-repo) | low | high | Helm repository reference detected |
| [`istio-destinationrule`](#istio-destinationrule) | low | high | Istio DestinationRule detected |
| [`istio-peer-authentication`](#istio-peer-authentication) | medium | high | Istio PeerAuthentication detected |
| [`istio-virtualservice`](#istio-virtualservice) | low | high | Istio VirtualService detected |
| [`jaeger-tracing`](#jaeger-tracing) | low | high | Distributed tracing configuration detected |
| [`kubernetes-endpoints`](#kubernetes-endpoints) | low | high | Kubernetes Endpoints detected |
| [`linkerd-service-profile`](#linkerd-service-profile) | low | high | Linkerd ServiceProfile detected |
| [`network-policy-egress`](#network-policy-egress) | medium | high | Network policy egress rule detected |
| [`network-policy-ingress`](#network-policy-ingress) | medium | high | Network policy ingress rule detected |
| [`pod-security-policy`](#pod-security-policy) | medium | high | PodSecurityPolicy detected |
| [`prometheus-metrics`](#prometheus-metrics) | low | high | Prometheus metrics endpoint detected |
| [`retry-policy`](#retry-policy) | low | high | Retry policy detected |
| [`timeout-configuration`](#timeout-configuration) | low | high | Timeout configuration detected |

## Pattern details

### api-gateway

API Gateway detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `api-gateway`, `microservices`, `ingress` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*APIGateway|Kong|Ambassador|nginx.*ingress
```

**Input that fires** (verified by the liveness test):

```text
kind: APIGateway
```

### aws-ecs-task

AWS ECS task definition detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `aws`, `ecs`, `container` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)AWS::ECS::TaskDefinition|Fargate
```

**Reference**: <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definitions.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
AWS::ECS::TaskDefi…on
```

### aws-eks-cluster

AWS EKS cluster detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `aws`, `eks`, `kubernetes` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)AWS::EKS::Cluster
```

**Reference**: <https://docs.aws.amazon.com/eks/latest/userguide/clusters.html>

**Input that fires** (verified by the liveness test):

```text
AWS::EKS::Cluster
```

### aws-lambda-function

AWS Lambda function reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `aws`, `lambda`, `serverless` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)AWSTemplateFormatVersion.*Lambda
```

**Reference**: <https://docs.aws.amazon.com/lambda/latest/dg/welcome.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
AWSTempl…S3.4rZLambda
```

### aws-sam-template

AWS SAM template detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `aws`, `sam`, `serverless` |

**Match pattern** (Rust `regex` syntax):

```regex
Transform:\s*AWS::Serverless
```

**Reference**: <https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html>

**Input that fires** (verified by the liveness test):

```text
Transform: AWS::Serverless
```

### azure-aks-cluster

Azure AKS cluster detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `azure`, `aks`, `kubernetes` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Microsoft\.ContainerService|aks
```

**Reference**: <https://docs.microsoft.com/en-us/azure/aks/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
Microsoft.Containe…ce
```

### azure-functions

Azure Functions detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `azure`, `functions`, `serverless` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Microsoft\.Web/sites|Functions
```

**Reference**: <https://docs.microsoft.com/en-us/azure/azure-functions/>

**Input that fires** (verified by the liveness test):

```text
Microsoft.Web/sites
```

### circuit-breaker

Circuit breaker pattern detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `circuit-breaker`, `resilience`, `microservices` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)circuitBreaker|CircuitBreaker|circuit_breaker
```

**Reference**: <https://martinfowler.com/bliki/CircuitBreaker.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
circuitB…er
```

### cloud-native-kubernetes-secret

Kubernetes Secret resource detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `secret`, `cloud` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Secret
```

**Reference**: <https://kubernetes.io/docs/concepts/configuration/secret/>

**Input that fires** (verified by the liveness test):

```text
kind: Secret
```

### cloud-native-kubernetes-service

Kubernetes Service detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `service`, `discovery` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Service
```

**Reference**: <https://kubernetes.io/docs/concepts/services-networking/service/>

**Input that fires** (verified by the liveness test):

```text
kind: Service
```

### consul-service

Consul service definition detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `consul`, `service-discovery`, `hashicorp` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)service\s*\{.*name.*}
```

**Reference**: <https://www.consul.io/docs/services>

**Input that fires** (verified by the liveness test):

```text
service {iUPCjCg@name7cuwYN9C}
```

### container-capabilities

Dangerous container capability added

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `capabilities` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)add:\s*\[.*(SYS_ADMIN|NET_ADMIN|ALL)
```

**Reference**: <https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
add: [LUJ5pHmA…IN
```

### container-liveness-probe

Container liveness probe configured

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `container`, `health` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)livenessProbe
```

**Reference**: <https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
liveness…be
```

### container-privileged

Privileged container detected

| Field | Value |
|-------|-------|
| Severity | `critical` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `container` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)privileged:\s*true
```

**Reference**: <https://kubernetes.io/docs/concepts/security/linux-namespaces/#privileged-containers>

**Input that fires** (verified by the liveness test):

```text
privileged: true
```

### container-readiness-probe

Container readiness probe configured

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `container`, `health` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)readinessProbe
```

**Reference**: <https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
readines…be
```

### container-resources

Container resource limits configured

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `container`, `resources` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)resources:\s*requests|resources:\s*limits
```

**Reference**: <https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/>

**Input that fires** (verified by the liveness test):

```text
resources: requests
```

### container-security-context

Container security context configured

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `container` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)securityContext
```

**Reference**: <https://kubernetes.io/docs/tasks/configure-pod-container/security-context/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
security…xt
```

### dockerfile-exposed

Potentially sensitive port exposed in Dockerfile

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `security`, `network` |

**Match pattern** (Rust `regex` syntax):

```regex
EXPOSE\s+(22|23|3306|5432|27017|6379|11211)
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#expose>

**Input that fires** (verified by the liveness test):

```text
EXPOSE 22
```

### elasticsearch-config

Elasticsearch configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `elasticsearch`, `logging`, `observability` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)elasticsearch|elastic.*search|ELK.*stack
```

**Reference**: <https://www.elastic.co/elasticsearch/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
elastics…ch
```

### etcd-service

etcd service configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `medium` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `etcd`, `service-discovery`, `kubernetes` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)etcd.*client|etcd.*peer
```

**Reference**: <https://etcd.io/docs/>

**Input that fires** (verified by the liveness test):

```text
etcdA_client
```

### fluentd-config

Fluentd logging configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `logging`, `fluentd`, `observability` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)fluentd|fluent-bit|logzio
```

**Reference**: <https://www.fluentd.org/>

**Input that fires** (verified by the liveness test):

```text
fluentd
```

### gcp-gke-cluster

GCP GKE cluster detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `gcp`, `gke`, `kubernetes` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)GKE|GoogleContainerEngine|container.googleapis.com
```

**Reference**: <https://cloud.google.com/kubernetes-engine>

**Input that fires** (verified by the liveness test):

```text
GKE
```

### google-cloud-function

Google Cloud Function detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `gcp`, `functions`, `serverless` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Google::Cloud::Functions
```

**Reference**: <https://cloud.google.com/functions/docs>

**Input that fires** (verified by the liveness test):

```text
Google::Cloud::Functions
```

### grafana-dashboard

Grafana dashboard detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `grafana`, `monitoring`, `dashboard` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)grafana|dashboard.*json
```

**Reference**: <https://grafana.com/docs/grafana/latest/dashboards/>

**Input that fires** (verified by the liveness test):

```text
grafana
```

### helm-release

Helm release detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `helm`, `kubernetes`, `deployment` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)HelmRelease|helm.*release
```

**Reference**: <https://helm.sh/docs/>

**Input that fires** (verified by the liveness test):

```text
HelmRelease
```

### helm-repo

Helm repository reference detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `helm`, `kubernetes`, `repository` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)helm.*repo.*add|helm.*repo.*update
```

**Reference**: <https://helm.sh/docs/helm/helm_repo/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
helmTjx5cfa.Cd6Dfrep…dd
```

### istio-destinationrule

Istio DestinationRule detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `istio`, `service-mesh`, `kubernetes` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*DestinationRule
```

**Reference**: <https://istio.io/latest/docs/reference/config/networking/destination-rule/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: Destinat…le
```

### istio-peer-authentication

Istio PeerAuthentication detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `istio`, `mtls`, `security` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*PeerAuthentication
```

**Reference**: <https://istio.io/latest/docs/reference/config/security/peer_authentication/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: PeerAuth…on
```

### istio-virtualservice

Istio VirtualService detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `istio`, `service-mesh`, `kubernetes` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*VirtualService
```

**Reference**: <https://istio.io/latest/docs/reference/config/networking/virtual-service/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: VirtualS…ce
```

### jaeger-tracing

Distributed tracing configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `tracing`, `observability`, `distributed` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)jaeger|opentracing|opentelemetry|traceId
```

**Reference**: <https://www.jaegertracing.io/>

**Input that fires** (verified by the liveness test):

```text
jaeger
```

### kubernetes-endpoints

Kubernetes Endpoints detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `service`, `endpoints` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Endpoints
```

**Reference**: <https://kubernetes.io/docs/concepts/services-networking/service/>

**Input that fires** (verified by the liveness test):

```text
kind: Endpoints
```

### linkerd-service-profile

Linkerd ServiceProfile detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `linkerd`, `service-mesh`, `kubernetes` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*ServiceProfile
```

**Reference**: <https://linkerd.io/2.14/reference/service-profiles/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: ServiceP…le
```

### network-policy-egress

Network policy egress rule detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `network`, `policy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)policyTypes.*Egress|egress.*CIDR
```

**Reference**: <https://kubernetes.io/docs/concepts/services-networking/network-policies/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
policyTy…ss
```

### network-policy-ingress

Network policy ingress rule detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `network`, `policy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)policyTypes.*Ingress|ingress.*CIDR
```

**Reference**: <https://kubernetes.io/docs/concepts/services-networking/network-policies/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
policyTy…ss
```

### pod-security-policy

PodSecurityPolicy detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `security`, `policy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*PodSecurityPolicy
```

**Reference**: <https://kubernetes.io/docs/concepts/security/pod-security-policy/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: PodSecur…cy
```

### prometheus-metrics

Prometheus metrics endpoint detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `prometheus`, `monitoring`, `metrics` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)prometheus|metrics.*endpoint|/metrics
```

**Reference**: <https://prometheus.io/docs/concepts/data_model/>

**Input that fires** (verified by the liveness test):

```text
prometheus
```

### retry-policy

Retry policy detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `retry`, `resilience`, `microservices` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)retryPolicy|RetryPolicy|retry_policy|maxAttempts
```

**Input that fires** (verified by the liveness test):

```text
retryPolicy
```

### timeout-configuration

Timeout configuration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `timeout`, `resilience`, `configuration` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)timeout:\s*\d+|requestTimeout|readTimeout
```

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
timeout: 44784677…32
```
