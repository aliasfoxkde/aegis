# infrastructure patterns

Infrastructure as code security

**55 patterns** in this category. Return to the
[pattern index](../README.md) for the other categories and scoring
reference.

## Summary

| Pattern | Severity | Confidence | Description |
|----------|----------|------------|-------------|
| [`cloudformation-conditions`](#cloudformation-conditions) | low | high | CloudFormation Conditions section detected |
| [`cloudformation-mappings`](#cloudformation-mappings) | low | high | CloudFormation Mappings section detected |
| [`cloudformation-outputs`](#cloudformation-outputs) | low | high | CloudFormation Outputs section detected |
| [`cloudformation-parameters`](#cloudformation-parameters) | low | high | CloudFormation Parameters section detected |
| [`cloudformation-resources`](#cloudformation-resources) | low | high | CloudFormation Resources section detected |
| [`cloudformation-template-format-version`](#cloudformation-template-format-version) | low | high | CloudFormation template version detected |
| [`dockerfile-add`](#dockerfile-add) | medium | high | Dockerfile ADD instruction detected |
| [`dockerfile-cmd`](#dockerfile-cmd) | low | high | Dockerfile CMD instruction detected |
| [`dockerfile-copy`](#dockerfile-copy) | low | high | Dockerfile COPY instruction detected |
| [`dockerfile-env`](#dockerfile-env) | medium | high | Dockerfile ENV instruction detected |
| [`dockerfile-expose`](#dockerfile-expose) | low | high | Dockerfile EXPOSE instruction detected |
| [`dockerfile-from`](#dockerfile-from) | low | high | Dockerfile FROM instruction detected |
| [`dockerfile-healthcheck`](#dockerfile-healthcheck) | low | high | Dockerfile HEALTHCHECK instruction detected |
| [`dockerfile-run`](#dockerfile-run) | low | high | Dockerfile RUN instruction detected |
| [`dockerfile-user`](#dockerfile-user) | low | high | Dockerfile USER instruction detected |
| [`dockerfile-volume`](#dockerfile-volume) | low | high | Dockerfile VOLUME instruction detected |
| [`dockerfile-workdir`](#dockerfile-workdir) | low | high | Dockerfile WORKDIR instruction detected |
| [`helm-chart`](#helm-chart) | low | high | Helm Chart detected (apiVersion v2) |
| [`helm-templates`](#helm-templates) | low | high | Helm template file detected |
| [`helm-values`](#helm-values) | low | high | Helm values file detected |
| [`kubernetes-clusterrole`](#kubernetes-clusterrole) | medium | high | Kubernetes ClusterRole detected |
| [`kubernetes-configmap`](#kubernetes-configmap) | low | high | Kubernetes ConfigMap detected |
| [`kubernetes-cronjob`](#kubernetes-cronjob) | low | high | Kubernetes CronJob detected |
| [`kubernetes-daemonset`](#kubernetes-daemonset) | low | high | Kubernetes DaemonSet detected |
| [`kubernetes-deployment`](#kubernetes-deployment) | low | high | Kubernetes Deployment detected |
| [`kubernetes-hpa`](#kubernetes-hpa) | low | high | Kubernetes HPA detected |
| [`kubernetes-ingress`](#kubernetes-ingress) | low | high | Kubernetes Ingress detected |
| [`kubernetes-job`](#kubernetes-job) | low | high | Kubernetes Job detected |
| [`kubernetes-limitrange`](#kubernetes-limitrange) | low | high | Kubernetes LimitRange detected |
| [`kubernetes-namespace`](#kubernetes-namespace) | low | high | Kubernetes Namespace detected |
| [`kubernetes-networkpolicy`](#kubernetes-networkpolicy) | medium | high | Kubernetes NetworkPolicy detected |
| [`kubernetes-pdb`](#kubernetes-pdb) | low | high | Kubernetes PodDisruptionBudget detected |
| [`kubernetes-persistentvolume`](#kubernetes-persistentvolume) | low | high | Kubernetes PersistentVolume detected |
| [`kubernetes-pod`](#kubernetes-pod) | low | high | Kubernetes Pod detected |
| [`kubernetes-priorityclass`](#kubernetes-priorityclass) | low | high | Kubernetes PriorityClass detected |
| [`kubernetes-resource-quota`](#kubernetes-resource-quota) | low | high | Kubernetes ResourceQuota detected |
| [`kubernetes-role`](#kubernetes-role) | medium | high | Kubernetes Role detected |
| [`kubernetes-secret`](#kubernetes-secret) | high | high | Kubernetes Secret detected |
| [`kubernetes-service`](#kubernetes-service) | low | high | Kubernetes Service detected |
| [`kubernetes-serviceaccount`](#kubernetes-serviceaccount) | low | high | Kubernetes ServiceAccount detected |
| [`kubernetes-statefulset`](#kubernetes-statefulset) | low | high | Kubernetes StatefulSet detected |
| [`terraform-backend`](#terraform-backend) | medium | high | Terraform backend configuration detected |
| [`terraform-count`](#terraform-count) | medium | high | Terraform count detected |
| [`terraform-data-source`](#terraform-data-source) | low | high | Terraform data source detected |
| [`terraform-dynamic-block`](#terraform-dynamic-block) | medium | high | Terraform dynamic block detected |
| [`terraform-for-each`](#terraform-for-each) | medium | high | Terraform for_each detected |
| [`terraform-locals`](#terraform-locals) | low | high | Terraform locals block detected |
| [`terraform-module`](#terraform-module) | low | high | Terraform module usage detected |
| [`terraform-output`](#terraform-output) | low | high | Terraform output definition detected |
| [`terraform-provider-aws`](#terraform-provider-aws) | low | high | AWS provider declaration detected |
| [`terraform-provider-azure`](#terraform-provider-azure) | low | high | Azure provider declaration detected |
| [`terraform-provider-gcp`](#terraform-provider-gcp) | low | high | GCP provider declaration detected |
| [`terraform-resource`](#terraform-resource) | low | high | Terraform resource definition detected |
| [`terraform-sensitive-variable`](#terraform-sensitive-variable) | high | high | Terraform sensitive variable detected |
| [`terraform-variable`](#terraform-variable) | low | high | Terraform variable definition detected |

## Pattern details

### cloudformation-conditions

CloudFormation Conditions section detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `conditions` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Conditions:
```

**Reference**: <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/conditions-section-structure.html>

**Input that fires** (verified by the liveness test):

```text
Conditions:
```

### cloudformation-mappings

CloudFormation Mappings section detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `mappings` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Mappings:
```

**Reference**: <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/mappings-section-structure.html>

**Input that fires** (verified by the liveness test):

```text
Mappings:
```

### cloudformation-outputs

CloudFormation Outputs section detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `outputs` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Outputs:
```

**Reference**: <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html>

**Input that fires** (verified by the liveness test):

```text
Outputs:
```

### cloudformation-parameters

CloudFormation Parameters section detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `parameters` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Parameters:
```

**Reference**: <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html>

**Input that fires** (verified by the liveness test):

```text
Parameters:
```

### cloudformation-resources

CloudFormation Resources section detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `infrastructure` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)Resources:
```

**Reference**: <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resources-section-structure.html>

**Input that fires** (verified by the liveness test):

```text
Resources:
```

### cloudformation-template-format-version

CloudFormation template version detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `cloudformation`, `aws`, `version` |

**Match pattern** (Rust `regex` syntax):

```regex
AWSTemplateFormatVersion:
```

**Reference**: <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-version.html>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
AWSTempl…on:
```

### dockerfile-add

Dockerfile ADD instruction detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `add` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^ADD\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#add>

**Input that fires** (verified by the liveness test):

```text
ADD 
```

### dockerfile-cmd

Dockerfile CMD instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `cmd` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^CMD\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#cmd>

**Input that fires** (verified by the liveness test):

```text
CMD 
```

### dockerfile-copy

Dockerfile COPY instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `copy` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^COPY\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#copy>

**Input that fires** (verified by the liveness test):

```text
COPY 
```

### dockerfile-env

Dockerfile ENV instruction detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `env` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^ENV\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#env>

**Input that fires** (verified by the liveness test):

```text
ENV 
```

### dockerfile-expose

Dockerfile EXPOSE instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `network` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^EXPOSE\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#expose>

**Input that fires** (verified by the liveness test):

```text
EXPOSE 
```

### dockerfile-from

Dockerfile FROM instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `container` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^FROM\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#from>

**Input that fires** (verified by the liveness test):

```text
FROM 
```

### dockerfile-healthcheck

Dockerfile HEALTHCHECK instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `healthcheck` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^HEALTHCHECK\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#healthcheck>

**Input that fires** (verified by the liveness test):

```text
HEALTHCHECK 
```

### dockerfile-run

Dockerfile RUN instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `run` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^RUN\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#run>

**Input that fires** (verified by the liveness test):

```text
RUN 
```

### dockerfile-user

Dockerfile USER instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `user` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^USER\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#user>

**Input that fires** (verified by the liveness test):

```text
USER 
```

### dockerfile-volume

Dockerfile VOLUME instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `volume` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^VOLUME\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#volume>

**Input that fires** (verified by the liveness test):

```text
VOLUME 
```

### dockerfile-workdir

Dockerfile WORKDIR instruction detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `docker`, `dockerfile`, `workdir` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)^WORKDIR\s+
```

**Reference**: <https://docs.docker.com/engine/reference/builder/#workdir>

**Input that fires** (verified by the liveness test):

```text
WORKDIR 
```

### helm-chart

Helm Chart detected (apiVersion v2)

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `helm`, `kubernetes`, `charts` |

**Match pattern** (Rust `regex` syntax):

```regex
apiVersion:\s*v2
```

**Reference**: <https://helm.sh/docs/topics/charts/>

**Input that fires** (verified by the liveness test):

```text
apiVersion: v2
```

### helm-templates

Helm template file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `helm`, `kubernetes`, `templates` |

**Match pattern** (Rust `regex` syntax):

```regex
templates/[^/]+\.ya?ml
```

**Reference**: <https://helm.sh/docs/chart_template_guide/>

**Input that fires** (verified by the liveness test):

```text
templates/r3b.yaml
```

### helm-values

Helm values file detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `helm`, `kubernetes`, `values` |

**Match pattern** (Rust `regex` syntax):

```regex
^values:
```

**Reference**: <https://helm.sh/docs/chart_best_practices/values/>

**Input that fires** (verified by the liveness test):

```text
values:
```

### kubernetes-clusterrole

Kubernetes ClusterRole detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `rbac` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*ClusterRole
```

**Reference**: <https://kubernetes.io/docs/reference/access-authn-authz/rbac/>

**Input that fires** (verified by the liveness test):

```text
kind: ClusterRole
```

### kubernetes-configmap

Kubernetes ConfigMap detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `configmap` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*ConfigMap
```

**Reference**: <https://kubernetes.io/docs/concepts/configuration/configmap/>

**Input that fires** (verified by the liveness test):

```text
kind: ConfigMap
```

### kubernetes-cronjob

Kubernetes CronJob detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `cronjob` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*CronJob
```

**Reference**: <https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/>

**Input that fires** (verified by the liveness test):

```text
kind: CronJob
```

### kubernetes-daemonset

Kubernetes DaemonSet detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `daemonset` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*DaemonSet
```

**Reference**: <https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/>

**Input that fires** (verified by the liveness test):

```text
kind: DaemonSet
```

### kubernetes-deployment

Kubernetes Deployment detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `deployment` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Deployment
```

**Reference**: <https://kubernetes.io/docs/concepts/workloads/controllers/deployment/>

**Input that fires** (verified by the liveness test):

```text
kind: Deployment
```

### kubernetes-hpa

Kubernetes HPA detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `autoscaling` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*HorizontalPodAutoscaler
```

**Reference**: <https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: Horizont…er
```

### kubernetes-ingress

Kubernetes Ingress detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `ingress` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Ingress
```

**Reference**: <https://kubernetes.io/docs/concepts/services-networking/ingress/>

**Input that fires** (verified by the liveness test):

```text
kind: Ingress
```

### kubernetes-job

Kubernetes Job detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `job` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Job
```

**Reference**: <https://kubernetes.io/docs/concepts/workloads/controllers/job/>

**Input that fires** (verified by the liveness test):

```text
kind: Job
```

### kubernetes-limitrange

Kubernetes LimitRange detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `limits` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*LimitRange
```

**Reference**: <https://kubernetes.io/docs/concepts/policy/limit-range/>

**Input that fires** (verified by the liveness test):

```text
kind: LimitRange
```

### kubernetes-namespace

Kubernetes Namespace detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `namespace` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Namespace
```

**Reference**: <https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/>

**Input that fires** (verified by the liveness test):

```text
kind: Namespace
```

### kubernetes-networkpolicy

Kubernetes NetworkPolicy detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `network` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*NetworkPolicy
```

**Reference**: <https://kubernetes.io/docs/concepts/services-networking/network-policies/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: NetworkP…cy
```

### kubernetes-pdb

Kubernetes PodDisruptionBudget detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `pdb` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*PodDisruptionBudget
```

**Reference**: <https://kubernetes.io/docs/concepts/workloads/pods/disruptions/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: PodDisru…et
```

### kubernetes-persistentvolume

Kubernetes PersistentVolume detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `persistence` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*PersistentVolume
```

**Reference**: <https://kubernetes.io/docs/concepts/storage/persistent-volumes/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: Persiste…me
```

### kubernetes-pod

Kubernetes Pod detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `pod` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Pod
```

**Reference**: <https://kubernetes.io/docs/concepts/workloads/pods/>

**Input that fires** (verified by the liveness test):

```text
kind: Pod
```

### kubernetes-priorityclass

Kubernetes PriorityClass detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `priority` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*PriorityClass
```

**Reference**: <https://kubernetes.io/docs/concepts/scheduling-eviction/pod-priority-preemption/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: Priority…ss
```

### kubernetes-resource-quota

Kubernetes ResourceQuota detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `quota` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*ResourceQuota
```

**Reference**: <https://kubernetes.io/docs/concepts/policy/resource-quotas/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: Resource…ta
```

### kubernetes-role

Kubernetes Role detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `rbac` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Role
```

**Reference**: <https://kubernetes.io/docs/reference/access-authn-authz/rbac/>

**Input that fires** (verified by the liveness test):

```text
kind: Role
```

### kubernetes-secret

Kubernetes Secret detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `secret` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Secret
```

**Reference**: <https://kubernetes.io/docs/concepts/configuration/secret/>

**Input that fires** (verified by the liveness test):

```text
kind: Secret
```

### kubernetes-service

Kubernetes Service detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `service` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*Service
```

**Reference**: <https://kubernetes.io/docs/concepts/services-networking/service/>

**Input that fires** (verified by the liveness test):

```text
kind: Service
```

### kubernetes-serviceaccount

Kubernetes ServiceAccount detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `serviceaccount` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*ServiceAccount
```

**Reference**: <https://kubernetes.io/docs/concepts/security/service-accounts/>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
kind: ServiceA…nt
```

### kubernetes-statefulset

Kubernetes StatefulSet detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `kubernetes`, `k8s`, `statefulset` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)kind:\s*StatefulSet
```

**Reference**: <https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/>

**Input that fires** (verified by the liveness test):

```text
kind: StatefulSet
```

### terraform-backend

Terraform backend configuration detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `backend` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)backend\s+"[^"]+"
```

**Reference**: <https://developer.hashicorp.com/terraform/language/settings/backends/configuration>

**Input that fires** (verified by the liveness test):

```text
backend "wT3iF+BhdrH"
```

### terraform-count

Terraform count detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `count` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)count\s*=
```

**Reference**: <https://developer.hashicorp.com/terraform/language/meta-arguments/count>

**Input that fires** (verified by the liveness test):

```text
count =
```

### terraform-data-source

Terraform data source detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `data` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)data\s+"[^"]+"
```

**Reference**: <https://developer.hashicorp.com/terraform/language/data-sources>

**Input that fires** (verified by the liveness test):

```text
data "=vZFsm.WLxxVT+NB"
```

### terraform-dynamic-block

Terraform dynamic block detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `dynamic` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)dynamic\s+"[^"]+"
```

**Reference**: <https://developer.hashicorp.com/terraform/language/expressions/dynamic-blocks>

**Input that fires** (verified by the liveness test):

```text
dynamic "HuAnzGb-Hd"
```

### terraform-for-each

Terraform for_each detected

| Field | Value |
|-------|-------|
| Severity | `medium` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `for-each` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)for_each\s*=
```

**Reference**: <https://developer.hashicorp.com/terraform/language/meta-arguments/for_each>

**Input that fires** (verified by the liveness test):

```text
for_each =
```

### terraform-locals

Terraform locals block detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `locals` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)locals\s*\{
```

**Reference**: <https://developer.hashicorp.com/terraform/language/values/locals>

**Input that fires** (verified by the liveness test):

```text
locals {
```

### terraform-module

Terraform module usage detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `module` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)module\s+"[^"]+"
```

**Reference**: <https://developer.hashicorp.com/terraform/language/modules>

**Input that fires** (verified by the liveness test):

```text
module "LfX Fse"
```

### terraform-output

Terraform output definition detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `output` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)output\s+"[^"]+"
```

**Reference**: <https://developer.hashicorp.com/terraform/language/values/outputs>

**Input that fires** (verified by the liveness test; long
token-shaped runs are elided here — the exact input is compiled into
`crates/aegis-patterns/src/examples.rs`):

```text
output "w_/Zgb83Xz9…aX"
```

### terraform-provider-aws

AWS provider declaration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `aws`, `provider` |

**Match pattern** (Rust `regex` syntax):

```regex
provider\s+"aws"
```

**Reference**: <https://registry.terraform.io/providers/hashicorp/aws/latest/docs>

**Input that fires** (verified by the liveness test):

```text
provider "aws"
```

### terraform-provider-azure

Azure provider declaration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `azure`, `provider` |

**Match pattern** (Rust `regex` syntax):

```regex
provider\s+"azurerm"
```

**Reference**: <https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs>

**Input that fires** (verified by the liveness test):

```text
provider "azurerm"
```

### terraform-provider-gcp

GCP provider declaration detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `gcp`, `provider` |

**Match pattern** (Rust `regex` syntax):

```regex
provider\s+"google"
```

**Reference**: <https://registry.terraform.io/providers/hashicorp/google/latest/docs>

**Input that fires** (verified by the liveness test):

```text
provider "google"
```

### terraform-resource

Terraform resource definition detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `infrastructure` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)resource\s+"[^"]+"
```

**Reference**: <https://developer.hashicorp.com/terraform/language/resources>

**Input that fires** (verified by the liveness test):

```text
resource "yg"
```

### terraform-sensitive-variable

Terraform sensitive variable detected

| Field | Value |
|-------|-------|
| Severity | `high` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `sensitive` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)sensitive\s*=\s*true
```

**Reference**: <https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output>

**Input that fires** (verified by the liveness test):

```text
sensitive = true
```

### terraform-variable

Terraform variable definition detected

| Field | Value |
|-------|-------|
| Severity | `low` |
| Confidence | `high` |
| Scope | `file content` |
| Applies to | every text file |
| Binary files | skipped |
| Tags | `terraform`, `iac`, `variable` |

**Match pattern** (Rust `regex` syntax):

```regex
(?i)variable\s+"[^"]+"
```

**Reference**: <https://developer.hashicorp.com/terraform/language/values/variables>

**Input that fires** (verified by the liveness test):

```text
variable "YLL"
```
