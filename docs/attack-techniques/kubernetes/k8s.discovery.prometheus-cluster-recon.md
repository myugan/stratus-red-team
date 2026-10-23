---
title: Perform Cluster Reconnaissance via Prometheus
---

# Perform Cluster Reconnaissance via Prometheus




Platform: Kubernetes

## Mappings

- MITRE ATT&CK
    - Discovery



## Description


Performs cluster reconnaissance by querying an unauthenticated Prometheus HTTP API endpoint, without touching the Kubernetes API.

Prometheus ships with no authentication enabled by default: the HTTP query API on port <code>9090</code> is accessible to anyone who can reach the service. Because kube-state-metrics translates Kubernetes object state into labeled time series, a single set of HTTP queries exposes the full cluster map — every monitored component and its namespace, every running container's image and version, every Service's cluster IP, and node details such as kernel version, container runtime, pod CIDR, and system UUID. The critical characteristic is that the discovery requires <b>zero Kubernetes API calls</b>: the Kubernetes API server audit log records nothing.

This technique is designed for local simulation.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a namespace.
- Deploy a mock unauthenticated "Prometheus" API (nginx serving <code>/api/v1/targets</code>, <code>/api/v1/query</code> and <code>/-/healthy</code>) backed by realistic kube-state-metrics series describing pods, services, and nodes, reachable at <code>prometheus-server.&lt;ns&gt;.svc.cluster.local:9090</code> without any authentication.

<span style="font-variant: small-caps;">Detonation</span>:

- Run a recon pod that locates the Prometheus service (via the injected <code>PROMETHEUS_SERVER_SERVICE_HOST</code>/<code>_PORT</code> environment variables) and executes the attack sequence against the Prometheus HTTP API: health check, target enumeration, and <code>kube_pod_container_info</code>, <code>kube_service_info</code>, and <code>kube_node_info</code> queries. The pod makes no Kubernetes API calls — its ServiceAccount token is intentionally left unmounted.

References:

- https://kubernetes-security.cloud/topics/cluster-reconnaissance-via-prometheus
- https://prometheus.io/docs/prometheus/latest/querying/api/
- https://www.sysdig.com/blog/exposed-prometheus-exploit-kubernetes-kubeconeu


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.discovery.prometheus-cluster-recon
```
## Detection


Because this technique generates no Kubernetes API server audit events, detection must happen at the network or Prometheus level:

<ul>
<li>Monitor Prometheus HTTP access logs for requests to <code>/api/v1/query</code> and <code>/api/v1/targets</code> from unexpected source pods or namespaces — especially queries for <code>kube_pod_container_info</code>, <code>kube_service_info</code>, and <code>kube_node_info</code>, which a legitimate dashboard rarely fetches in bulk from an unknown client.</li>
<li>Alert on the absence of authentication: verify Prometheus is configured with <code>--web.config.file</code> (TLS/basic auth) or is fronted by an authenticating reverse proxy; an unauthenticated 200 response to <code>/-/healthy</code> from a non-scrape source is a red flag.</li>
<li>Use NetworkPolicies to restrict ingress to the Prometheus Service to known scraper or dashboard namespaces; a NetworkPolicy <code>deny</code> event for a random pod attempting port 9090 is a strong signal.</li>
<li>Watch for recon pods performing DNS lookups for <code>prometheus-server</code> or reading injected <code>PROMETHEUS_*</code> environment variables, e.g. via eBPF-based runtime sensors.</li>
</ul>


