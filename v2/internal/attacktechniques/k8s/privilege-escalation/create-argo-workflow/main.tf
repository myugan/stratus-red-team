terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.13.0"
    }
  }
}

locals {
  kubeconfig_path = pathexpand("~/.kube/config")

  labels = {
    "datadoghq.com/stratus-red-team" : true
    "datadoghq.com/stratus-red-team-correlation-id" : var.correlation.id
    "datadoghq.com/stratus-red-team-stage" : "warmup"
  }

  create_namespace  = var.config.kubernetes.namespace == ""
  generated_ns_name = format("stratus-red-team-argo-workflow-%s", var.correlation.short)
  namespace         = local.create_namespace ? local.generated_ns_name : var.config.kubernetes.namespace
}

# Use ~/.kube/config as a configuration file if it exists (with current context).
# Fallback to using in-cluster configuration
# see https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs#authentication
provider "kubernetes" {
  config_path = fileexists(local.kubeconfig_path) ? local.kubeconfig_path : null
}

resource "kubernetes_namespace" "namespace" {
  count = local.create_namespace ? 1 : 0
  metadata {
    name   = local.generated_ns_name
    labels = local.labels
  }
}

# Install a minimal Argo Workflows "Workflow" CRD so this technique can be
# simulated locally on a cluster that does NOT have Argo Workflows installed.
# Because no Argo controller is running, the malicious Workflow created at
# detonation time is never reconciled and no workload is actually deployed: the
# value is the audit-log signal (creation of an argoproj.io/v1alpha1 Workflow)
# itself.
#
# If the target cluster already runs Argo Workflows, the real CRD is already
# present and this resource will conflict. In that case, point the technique at
# the existing installation and remove this resource. This warm-up targets the
# local-simulation use case on a bare cluster (e.g. kind, minikube, k3d).
resource "kubernetes_manifest" "argo_workflow_crd" {
  manifest = {
    apiVersion = "apiextensions.k8s.io/v1"
    kind       = "CustomResourceDefinition"
    metadata = {
      name   = "workflows.argoproj.io"
      labels = local.labels
    }
    spec = {
      group = "argoproj.io"
      scope = "Namespaced"
      names = {
        plural     = "workflows"
        singular   = "workflow"
        kind       = "Workflow"
        shortNames = ["wf"]
      }
      versions = [
        {
          name    = "v1alpha1"
          served  = true
          storage = true
          schema = {
            openAPIV3Schema = {
              type                                   = "object"
              "x-kubernetes-preserve-unknown-fields" = true
            }
          }
        }
      ]
    }
  }
}

output "namespace" {
  value = local.namespace
}

output "warmup_short_id" {
  value = var.correlation.short
}

output "display" {
  value = format("Argo Workflows Workflow CRD installed and namespace %s ready", local.namespace)
}
