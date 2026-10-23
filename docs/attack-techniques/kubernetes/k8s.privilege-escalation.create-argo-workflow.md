---
title: Create Malicious Argo Workflow
---

# Create Malicious Argo Workflow




Platform: Kubernetes

## Mappings

- MITRE ATT&CK
    - Privilege Escalation
  - Execution



## Description


Submits a malicious <code>Workflow</code> to the Argo Workflows API that executes arbitrary commands under a privileged ServiceAccount.

Argo's controller acts as a confused deputy: it reads the workflow spec as a trusted instruction and creates the workflow pods using its own, typically highly-privileged, Kubernetes credentials. An attacker who only holds the Argo-level permission <code>create workflows</code> (commonly granted to CI/CD service accounts) can therefore have arbitrary workloads run with the permissions of any ServiceAccount in the namespace — their own Kubernetes RBAC is irrelevant. The workflow output (e.g. dumped secrets) can be exfiltrated through the Argo API logs endpoint without any Kubernetes RBAC. The <code>generateName</code> prefix mimics legitimate CI/CD naming conventions (masquerading).

This technique is designed for local simulation.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a namespace.
- Install a minimal Argo Workflows <code>Workflow</code> CustomResourceDefinition, so the technique can be simulated on a cluster that does not have Argo Workflows installed.

<span style="font-variant: small-caps;">Detonation</span>:

- Create an <code>argoproj.io/v1alpha1</code> <code>Workflow</code> with a <code>generateName</code> prefix mimicking CI/CD pipelines, whose container runs an attacker command and requests a privileged <code>serviceAccountName</code>.

Note: because no Argo controller is running in the local-simulation setup, the Workflow is never reconciled and no pod is actually created. The emulated signal is the creation of the malicious Workflow object itself. Against a cluster that already runs Argo Workflows, the controller would schedule the pod with the requested ServiceAccount.

References:

- https://kubernetes-security.cloud/topics/weaponizing-argo-workflows
- https://argo-workflows.readthedocs.io/en/stable/security/
- https://argo-workflows.readthedocs.io/en/stable/workflow-restrictions/


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate k8s.privilege-escalation.create-argo-workflow
```
## Detection


Monitor the Kubernetes audit logs for <code>create</code> operations on <code>workflows.argoproj.io</code> objects.

Alert in particular on Argo Workflows that:
<ul>
<li>specify a <code>serviceAccountName</code> more privileged than the submitter's own identity (privilege escalation via the controller's confused-deputy behavior);</li>
<li>use a <code>generateName</code> prefix that mimics legitimate CI/CD pipeline naming conventions (masquerading);</li>
<li>run container images or commands outside of your approved allowlist, especially commands reading service account tokens or listing secrets.</li>
</ul>

Also alert on API access patterns: workflows created by identities that do not normally submit workflows, and workflow log reads (<code>GET /api/v1/workflows/&lt;ns&gt;/&lt;name&gt;/log</code>) by non-CI/CD identities.

Where possible, restrict <code>workflows create</code> permissions to dedicated CI/CD service accounts, and enable Argo Workflows <code>workflowRestrictions</code> to limit allowed container images, ServiceAccounts, and volume types.


