# Based off https://github.com/nats-io/k8s/blob/53bfb34f36bfcd08a9434c558b6b77fa9081118a/nats-server/simple-nats.yml

locals {
  nats_labels = { "app" = "nats" }
}

resource "tls_private_key" "nats_ca_key" {
  algorithm   = var.private_key_alg
  rsa_bits    = var.private_key_alg == "RSA" ? 4096 : null
  ecdsa_curve = var.private_key_alg == "ECDSA" ? "P384" : null
}

resource "tls_self_signed_cert" "nats_ca_cert" {
  key_algorithm   = var.private_key_alg
  private_key_pem = tls_private_key.nats_ca_key.private_key_pem

  subject {
    common_name  = "Micro Shared Infrastructure"
    organization = "Micro"
  }

  validity_period_hours = 876000

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "client_auth",
    "server_auth",
  ]
  is_ca_certificate = true
}

resource "kubernetes_secret" "nats_ca" {
  type = "Opaque"
  metadata {
    name      = "nats-ca"
    namespace = kubernetes_namespace.resource_namespace.id
  }
  data = {
    "key.pem" = tls_private_key.nats_ca_key.private_key_pem
    "ca.pem"  = tls_self_signed_cert.nats_ca_cert.cert_pem
  }
}

resource "tls_private_key" "nats_server_key" {
  algorithm   = var.private_key_alg
  rsa_bits    = var.private_key_alg == "RSA" ? 4096 : null
  ecdsa_curve = var.private_key_alg == "ECDSA" ? "P384" : null
}

resource "tls_cert_request" "nats_server_cert" {
  key_algorithm   = var.private_key_alg
  private_key_pem = tls_private_key.nats_server_key.private_key_pem

  subject {
    common_name         = "*.nats.${kubernetes_namespace.resource_namespace.id}.svc"
    organization        = "Micro"
    organizational_unit = "Micro shared Infra"
  }
  dns_names = [
    "*.nats",
    "*.nats.${kubernetes_namespace.resource_namespace.id}",
    "*.nats.${kubernetes_namespace.resource_namespace.id}.svc",
    "*.nats.${kubernetes_namespace.resource_namespace.id}.svc.cluster.local",
    "nats-cluster",
    "nats-cluster.${kubernetes_namespace.resource_namespace.id}",
    "nats-cluster.${kubernetes_namespace.resource_namespace.id}.svc",
    "nats-cluster.${kubernetes_namespace.resource_namespace.id}.svc.cluster.local",
  ]
}

resource "tls_locally_signed_cert" "nats_server_cert" {
  cert_request_pem      = tls_cert_request.nats_server_cert.cert_request_pem
  ca_key_algorithm      = var.private_key_alg
  ca_private_key_pem    = tls_private_key.nats_ca_key.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.nats_ca_cert.cert_pem
  validity_period_hours = 87600
  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
    "server_auth"
  ]
  is_ca_certificate = false
}

resource "kubernetes_secret" "nats_certs" {
  type = "Opaque"
  metadata {
    name      = "nats-certs"
    namespace = kubernetes_namespace.resource_namespace.id
  }
  data = {
    "ca.pem"   = tls_self_signed_cert.nats_ca_cert.cert_pem
    "cert.pem" = tls_locally_signed_cert.nats_server_cert.cert_pem
    "key.pem"  = tls_private_key.nats_server_key.private_key_pem
  }
}

resource "kubernetes_config_map" "nats_server" {
  metadata {
    namespace = kubernetes_namespace.resource_namespace.id
    name      = "nats-config"
  }
  data = {
    "nats.conf" = <<-NATSCONF
      pid_file: "/var/run/nats/nats.pid"
      http: 8222

      tls {
        cert_file: "/certs/cert.pem"
        key_file: "/certs/key.pem"
        ca_file: "/certs/ca.pem"
        verify: true
      }

      cluster {
        port: 6222
        routes [
          nats://nats-0.nats.${kubernetes_namespace.resource_namespace.id}.svc:6222
          nats://nats-1.nats.${kubernetes_namespace.resource_namespace.id}.svc:6222
          nats://nats-2.nats.${kubernetes_namespace.resource_namespace.id}.svc:6222
        ]

        cluster_advertise: $CLUSTER_ADVERTISE
        connect_retries: 30
      }
    NATSCONF
  }
}

locals {
  nats_ports = {
    "client"    = 4222,
    "cluster"   = 6222,
    "monitor"   = 8222,
    "metrics"   = 7777,
    "leafnodes" = 7422,
    "gateways"  = 7522,
  }
}

resource "kubernetes_service" "nats" {
  metadata {
    namespace = kubernetes_namespace.resource_namespace.id
    name      = "nats"
    labels    = local.nats_labels
  }
  spec {
    selector   = local.nats_labels
    cluster_ip = "None"
    dynamic "port" {
      for_each = local.nats_ports
      content {
        name = port.key
        port = port.value
      }
    }
  }
}

resource "kubernetes_service" "nats_cluster" {
  metadata {
    namespace = kubernetes_namespace.resource_namespace.id
    name      = "nats-cluster"
    labels    = local.nats_labels
  }
  spec {
    selector = local.nats_labels
    port {
      name        = "client"
      port        = lookup(local.nats_ports, "client", 4222)
      target_port = "client"
    }
  }
}

resource "kubernetes_stateful_set" "nats" {
  metadata {
    namespace = kubernetes_namespace.resource_namespace.id
    name      = "nats"
    labels    = local.nats_labels
  }
  spec {
    replicas     = 3
    service_name = "nats"
    selector {
      match_labels = local.nats_labels
    }
    template {
      metadata {
        labels = local.nats_labels
      }
      spec {
        volume {
          name = "config-volume"
          config_map {
            default_mode = "0644"
            name         = kubernetes_config_map.nats_server.metadata.0.name
          }
        }
        volume {
          name = "pid"
          empty_dir {}
        }
        volume {
          name = "tls"
          secret {
            default_mode = "0600"
            secret_name  = kubernetes_secret.nats_certs.metadata.0.name
          }
        }
        share_process_namespace          = true
        termination_grace_period_seconds = 60
        container {
          name              = "nats"
          image             = var.nats_image
          image_pull_policy = var.image_pull_policy
          dynamic "port" {
            for_each = local.nats_ports
            content {
              name           = port.key
              container_port = port.value
            }
          }
          command = [
            "nats-server",
            "--config",
            "/etc/nats-config/nats.conf"
          ]
          env {
            name = "POD_NAME"
            value_from {
              field_ref {
                field_path = "metadata.name"
              }
            }
          }
          env {
            name = "POD_NAMESPACE"
            value_from {
              field_ref {
                field_path = "metadata.namespace"
              }
            }
          }
          env {
            name  = "CLUSTER_ADVERTISE"
            value = "$(POD_NAME).nats.$(POD_NAMESPACE).svc"
          }
          volume_mount {
            name       = "config-volume"
            mount_path = "/etc/nats-config"
          }
          volume_mount {
            name       = "pid"
            mount_path = "/var/run/nats"
          }
          volume_mount {
            name       = "tls"
            mount_path = "/certs"
          }
          liveness_probe {
            http_get {
              path = "/"
              port = lookup(local.nats_ports, "monitor", 8222)
            }
            initial_delay_seconds = 10
            timeout_seconds       = 5
          }
          readiness_probe {
            http_get {
              path = "/"
              port = lookup(local.nats_ports, "monitor", 8222)
            }
            initial_delay_seconds = 10
            timeout_seconds       = 5
          }
          lifecycle {
            pre_stop {
              exec {
                command = [
                  "/bin/sh", "-c", "/nats-server -sl=ldm=/var/run/nats/nats.pid && /bin/sleep 60"
                ]
              }
            }
          }
        }
      }
    }
    update_strategy {
      type = "RollingUpdate"
    }
  }
  depends_on = [kubernetes_config_map.nats_server]
}

resource "kubernetes_pod_disruption_budget" "nats" {
  metadata {
    name      = "nats"
    namespace = kubernetes_namespace.resource_namespace.id
  }
  spec {
    max_unavailable = "1"
    selector {
      match_labels = local.nats_labels
    }
  }
}
