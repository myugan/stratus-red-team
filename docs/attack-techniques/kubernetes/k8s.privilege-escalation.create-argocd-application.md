---
title: Create Malicious Argo CD Application
---

# Create Malicious Argo CD Application




Platform: Kubernetes

## Mappings

- MITRE ATT&CK
    - Privilege Escalation
  - Persistence



## Description


Creates a rogue Argo CD <code>Application</code> custom resource that points at an attacker-controlled Git repository.

Argo CD's application controller acts as a confused deputy: it reconciles Application resources by applying the manifests found in the referenced repository using its own, typically highly-privileged, Kubernetes credentials (often effectively cluster-admin). An attacker who can only create Application objects can therefore have arbitrary workloads deployed with the controller's permissions, without holding those permissions themselves. Enabling automated self-heal sync also provides persistence, as the controller recreates deleted resources.

This technique is designed for local simulation.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a namespace.
- Install a minimal Argo CD <code>Application</code> CustomResourceDefinition, so the technique can be simulated on a cluster that does not have Argo CD installed.

<span style="font-variant: small-caps;">Detonation</span>:

- Create an <code>argoproj.io/v1alpha1</code> <code>Application</code> that references an external Git repository, targets the in-cluster API server, and enables automated self-heal sync.

Note: because no Argo CD application controller is running in the local-simulation setup, the Application is never reconciled and no workload is actually deployed. The emulated signal is the creation of the rogue Application object itself. Against a cluster that already runs Argo CD, point the technique at the existing installation.

References:

- https://kubernetes-security.cloud/topics/weaponizing-argocd-application
- https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/
- https://argo-cd.readthedocs.io/en/stable/user-guide/projects/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.privilege-escalation.create-argocd-application
```
## Detection


Monitor the Kubernetes audit logs for <code>create</code> operations on <code>applications.argoproj.io</code> objects.

Alert in particular on Argo CD Applications that:
<ul>
<li>reference a <code>spec.source.repoURL</code> that is not in your approved repository allowlist;</li>
<li>enable <code>spec.syncPolicy.automated.selfHeal</code>, which the controller uses to recreate deleted resources (persistence);</li>
<li>target sensitive destination namespaces such as <code>argocd</code> or <code>kube-system</code>, or the in-cluster API server <code>https://kubernetes.default.svc</code>.</li>
</ul>

Where possible, constrain which users can create Applications through Argo CD RBAC, and restrict permitted source repositories and destinations using Argo CD AppProjects.


