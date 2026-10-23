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
  generated_ns_name = format("stratus-red-team-prometheus-recon-%s", var.correlation.short)
  namespace         = local.create_namespace ? local.generated_ns_name : var.config.kubernetes.namespace

  # Mock Prometheus API responses served by nginx. The responses mimic the
  # output of an unauthenticated Prometheus instance scraping kube-state-metrics
  # in a monitoring namespace, as described in
  # https://kubernetes-security.cloud/topics/cluster-reconnaissance-via-prometheus
  prometheus_config = <<-EOT
    map $arg_query $query_response {
      default '{"status":"success","data":{"resultType":"vector","result":[]},"status":"success"}';
      "kube_pod_container_info" '{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"kube_pod_container_info","namespace":"argocd","pod":"argocd-repo-server-779879c89d-fwmxp","container":"argocd-repo-server","image":"quay.io/argoproj/argocd","image_id":"quay.io/argoproj/argocd@sha256:deadbeef"},"value":["1730000000.000","1"]},{"metric":{"__name__":"kube_pod_container_info","namespace":"istio-system","pod":"istiod-6b4df59d4b-lsbzz","container":"discovery","image":"istio/pilot","image_id":"istio/pilot@sha256:cafebabe"},"value":["1730000000.000","1"]},{"metric":{"__name__":"kube_pod_container_info","namespace":"kube-system","pod":"kube-apiserver-timbernetes-xv444-lq4bq","container":"kube-apiserver","image":"registry.k8s.io/kube-apiserver","image_id":"registry.k8s.io/kube-apiserver@sha256:feedface"},"value":["1730000000.000","1"]}]},"status":"success"}';
      "kube_service_info" '{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"kube_service_info","namespace":"argocd","service":"argocd-server","cluster_ip":"10.105.10.15"},"value":["1730000000.000","1"]},{"metric":{"__name__":"kube_service_info","namespace":"kube-system","service":"kube-dns","cluster_ip":"10.96.0.10"},"value":["1730000000.000","1"]}]},"status":"success"}';
      "kube_node_info" '{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"kube_node_info","node":"timbernetes-xv444-lq4bq","container_runtime_version":"containerd://1.7.27","internal_ip":"10.245.132.25","kernel_version":"6.8.0-71-generic","kubelet_version":"v1.35.0","os_image":"Ubuntu 24.04.3 LTS","pod_cidr":"10.244.0.0/24","system_uuid":"e366bd4b77b9d6be2d67552f69964f40"},"value":["1730000000.000","1"]}]},"status":"success"}';
    }
    server {
      listen 9090 default_server;
      location = /-/healthy {
        default_type text/plain;
        return 200 "Prometheus Server is Healthy.\n";
      }
      location = /api/v1/targets {
        default_type application/json;
        return 200 '{"status":"success","data":{"activeTargets":[{"discoveredLabels":{"__address__":"10.244.0.5:8080","__metrics_path__":"/metrics","job":"kube-state-metrics"},"labels":{"job":"kube-state-metrics","namespace":"monitoring","pod":"kube-state-metrics-6b7f9d8c4d-x2k7m"},"scrapeUrl":"http://10.244.0.5:8080/metrics"},{"discoveredLabels":{"__address__":"10.244.0.6:9100","__metrics_path__":"/metrics","job":"node-exporter"},"labels":{"job":"node-exporter","namespace":"monitoring","pod":"prometheus-node-exporter-abcde"},"scrapeUrl":"http://10.244.0.6:9100/metrics"}],"droppedTargets":[]},"status":"success"}';
      }
      location = /api/v1/query {
        default_type application/json;
        return 200 $query_response;
      }
    }
  EOT

  kube_state_metrics_config = <<-EOT
    server {
      listen 8080 default_server;
      location = /metrics {
        default_type text/plain;
        return 200 "kube_pod_container_info{namespace=\"argocd\",pod=\"argocd-repo-server-779879c89d-fwmxp\",container=\"argocd-repo-server\",image=\"quay.io/argoproj/argocd\",image_id=\"quay.io/argoproj/argocd@sha256:deadbeef\",container_id=\"containerd://aaa\"} 1\nkube_pod_container_info{namespace=\"istio-system\",pod=\"istiod-6b4df59d4b-lsbzz\",container=\"discovery\",image=\"istio/pilot\",image_id=\"istio/pilot@sha256:cafebabe\",container_id=\"containerd://bbb\"} 1\nkube_pod_container_info{namespace=\"kube-system\",pod=\"kube-apiserver-timbernetes\",container=\"kube-apiserver\",image=\"registry.k8s.io/kube-apiserver\",image_id=\"registry.k8s.io/kube-apiserver@sha256:feedface\",container_id=\"containerd://ccc\"} 1\nkube_service_info{namespace=\"argocd\",service=\"argocd-server\",cluster_ip=\"10.105.10.15\",external_name=\"\",label_app_kubernetes_io_name=\"argocd\"} 1\nkube_service_info{namespace=\"kube-system\",service=\"kube-dns\",cluster_ip=\"10.96.0.10\",external_name=\"\",label_k8s_app=\"kube-dns\"} 1\nkube_node_info{node=\"timbernetes-xv444-lq4bq\",container_runtime_version=\"containerd://1.7.27\",internal_ip=\"10.245.132.25\",kernel_version=\"6.8.0-71-generic\",kubelet_version=\"v1.35.0\",os_image=\"Ubuntu 24.04.3 LTS\",pod_cidr=\"10.244.0.0/24\",system_uuid=\"e366bd4b77b9d6be2d67552f69964f40\"} 1\n";
      }
    }
  EOT
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

# Mock "Prometheus" API: an nginx server exposing the subset of the Prometheus
# HTTP API used by the technique (/api/v1/targets, /api/v1/query, /-/healthy),
# without authentication, as is Prometheus' default. The /api/v1/query endpoint
# is backed by realistic kube-state-metrics series served from a second nginx
# endpoint that acts as the scrape target, so the recon pod can harvest cluster
# topology (container images, services, node details) without touching the
# Kubernetes API.
resource "kubernetes_config_map" "prometheus_mock" {
  metadata {
    name      = format("prometheus-mock-%s", var.correlation.short)
    namespace = local.namespace
    labels    = local.labels
  }

  data = {
    "prometheus.conf"         = local.prometheus_config
    "kube-state-metrics.conf" = local.kube_state_metrics_config
  }
}

resource "kubernetes_deployment" "prometheus_mock" {
  metadata {
    name      = format("prometheus-server-%s", var.correlation.short)
    namespace = local.namespace
    labels    = local.labels
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = format("prometheus-mock-%s", var.correlation.short)
      }
    }

    template {
      metadata {
        labels = {
          app = format("prometheus-mock-%s", var.correlation.short)
        }
      }

      spec {
        container {
          name  = "prometheus"
          image = "nginx:1.27-alpine"

          port {
            container_port = 9090
          }

          volume_mount {
            name       = "prometheus-config"
            mount_path = "/etc/nginx/conf.d"
            read_only  = true
          }
        }

        container {
          name  = "kube-state-metrics"
          image = "nginx:1.27-alpine"

          port {
            container_port = 8080
          }

          command = ["/bin/sh", "-c"]
          args    = ["cp /config/kube-state-metrics.conf /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'"]

          volume_mount {
            name       = "ksm-config"
            mount_path = "/config"
            read_only  = true
          }

          volume_mount {
            name       = "nginx-default-empty"
            mount_path = "/etc/nginx/conf.d"
            read_only  = false
          }
        }

        volume {
          name = "prometheus-config"
          config_map {
            name = kubernetes_config_map.prometheus_mock.metadata[0].name
            items {
              key  = "prometheus.conf"
              path = "prometheus.conf"
            }
          }
        }

        volume {
          name = "ksm-config"
          config_map {
            name = kubernetes_config_map.prometheus_mock.metadata[0].name
            items {
              key  = "kube-state-metrics.conf"
              path = "kube-state-metrics.conf"
            }
          }
        }

        volume {
          name = "nginx-default-empty"
          empty_dir {}
        }
      }
    }
  }
}

# The kube-state-metrics scrape target, served by the second nginx container.
# The Prometheus API returns this as its only active target.
resource "kubernetes_service" "kube_state_metrics" {
  metadata {
    name      = format("kube-state-metrics-%s", var.correlation.short)
    namespace = local.namespace
    labels    = local.labels
  }

  spec {
    selector = {
      app = format("prometheus-mock-%s", var.correlation.short)
    }

    port {
      name        = "http"
      port        = 8080
      target_port = "8080"
    }
  }
}

# The unauthenticated Prometheus HTTP API, reachable from any pod in the
# cluster with network access to this namespace.
resource "kubernetes_service" "prometheus" {
  metadata {
    name      = "prometheus-server"
    namespace = local.namespace
    labels    = local.labels
  }

  spec {
    selector = {
      app = format("prometheus-mock-%s", var.correlation.short)
    }

    port {
      name        = "http"
      port        = 9090
      target_port = "9090"
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
  value = format("Mock unauthenticated Prometheus API ready at prometheus-server.%s.svc.cluster.local:9090", local.namespace)
}
