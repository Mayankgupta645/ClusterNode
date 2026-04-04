"""Mock Kubernetes cluster data generator for testing and demonstration"""
import random
import uuid
from typing import Dict, List, Any
from datetime import datetime, timedelta

class MockK8sCluster:
    """Generates realistic mock Kubernetes cluster data"""
    
    def __init__(self, mode="random", num_pods=20, num_service_accounts=15, num_roles=12, num_secrets=10):
        self.mode = random.choice(["low", "medium", "high"]) if mode == "random" else mode
        self.num_pods = num_pods
        self.num_service_accounts = num_service_accounts
        self.num_roles = num_roles
        self.num_secrets = num_secrets
            
        # Mock CVE database
        self.cve_database = {
            "nginx:1.19": {"cve_id": "CVE-2021-23017", "cvss_score": 8.1, "severity": "HIGH"},
            "redis:5.0": {"cve_id": "CVE-2021-32675", "cvss_score": 7.5, "severity": "HIGH"},
            "postgres:12": {"cve_id": "CVE-2021-32027", "cvss_score": 6.5, "severity": "MEDIUM"},
            "ubuntu:18.04": {"cve_id": "CVE-2021-3711", "cvss_score": 9.8, "severity": "CRITICAL"},
            "alpine:3.12": {"cve_id": "CVE-2021-36159", "cvss_score": 5.3, "severity": "MEDIUM"},
        }
        
    def generate_cluster_data(self) -> Dict[str, Any]:
        """Generate complete mock cluster data"""
        pods = self._generate_pods()
        service_accounts = self._generate_service_accounts()
        roles = self._generate_roles()
        secrets = self._generate_secrets()
        role_bindings = self._generate_role_bindings(pods, service_accounts, roles)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "cluster_name": "prod-cluster",
            "pods": pods,
            "service_accounts": service_accounts,
            "roles": roles,
            "secrets": secrets,
            "role_bindings": role_bindings,
            "metadata": {
                "total_nodes": len(pods) + len(service_accounts) + len(roles) + len(secrets),
                "namespaces": ["default", "kube-system", "production", "staging"],
            }
        }
    
    def _generate_pods(self) -> List[Dict[str, Any]]:
        """Generate mock pod data"""
        pod_names = [
            "api-server", "web-frontend", "auth-service", "payment-gateway",
            "data-processor", "cache-service", "monitoring-agent", "log-collector",
            "worker-1", "worker-2", "scheduler", "queue-manager",
            "ml-service", "notification-service", "analytics-engine",
            "backup-service", "cdn-proxy", "database-proxy", "redis-master", "etcd-node"
        ]
        
        images = list(self.cve_database.keys())
        pods = []
        
        for i, name in enumerate(pod_names[:self.num_pods]):
            image = random.choice(images)
            cve_info = self.cve_database.get(image, {})
            
            pod = {
                "id": f"pod-{uuid.uuid4().hex[:8]}",
                "name": name,
                "namespace": random.choice(["default", "production", "staging"]),
                "image": image,
                "type": "Pod",
                "created": (datetime.now() - timedelta(days=random.randint(1, 90))).isoformat(),
                "is_privileged": random.choice([True, False]),
                "exposed_to_internet": i < 5,  # First 5 pods are internet-facing
                "cve": cve_info,
                "labels": {
                    "app": name,
                    "tier": random.choice(["frontend", "backend", "database"]),
                    "env": random.choice(["prod", "staging"])
                }
            }
            pods.append(pod)
        
        return pods
    
    def _generate_service_accounts(self) -> List[Dict[str, Any]]:
        """Generate mock service account data"""
        sa_names = [
            "svc-admin", "svc-monitor", "svc-deploy", "svc-reader",
            "svc-operator", "svc-controller", "svc-webhook", "svc-scheduler",
            "svc-backup", "svc-cron", "svc-job-runner", "svc-api-gateway",
            "svc-auth-provider", "svc-secret-manager", "svc-network-policy"
        ]
        
        service_accounts = []
        for name in sa_names[:self.num_service_accounts]:
            sa = {
                "id": f"sa-{uuid.uuid4().hex[:8]}",
                "name": name,
                "namespace": random.choice(["default", "kube-system", "production"]),
                "type": "ServiceAccount",
                "auto_mount_token": True,
                "created": (datetime.now() - timedelta(days=random.randint(30, 180))).isoformat(),
            }
            service_accounts.append(sa)
        
        return service_accounts
    
    def _generate_roles(self) -> List[Dict[str, Any]]:
        """Generate mock role data"""
        role_configs = [
            {"name": "cluster-admin", "scope": "cluster", "permissions": ["*"], "risk": "CRITICAL"},
            {"name": "admin", "scope": "namespace", "permissions": ["*"], "risk": "HIGH"},
            {"name": "secret-reader", "scope": "namespace", "permissions": ["secrets:get", "secrets:list"], "risk": "HIGH"},
            {"name": "pod-exec", "scope": "namespace", "permissions": ["pods:exec", "pods:attach"], "risk": "HIGH"},
            {"name": "etcd-access", "scope": "cluster", "permissions": ["etcd:read", "etcd:write"], "risk": "CRITICAL"},
            {"name": "node-admin", "scope": "cluster", "permissions": ["nodes:*"], "risk": "HIGH"},
            {"name": "secret-writer", "scope": "namespace", "permissions": ["secrets:*"], "risk": "HIGH"},
            {"name": "configmap-reader", "scope": "namespace", "permissions": ["configmaps:get"], "risk": "MEDIUM"},
            {"name": "pod-reader", "scope": "namespace", "permissions": ["pods:get", "pods:list"], "risk": "LOW"},
            {"name": "service-viewer", "scope": "namespace", "permissions": ["services:get"], "risk": "LOW"},
            {"name": "rbac-manager", "scope": "cluster", "permissions": ["rbac:*"], "risk": "CRITICAL"},
            {"name": "namespace-admin", "scope": "namespace", "permissions": ["*"], "risk": "HIGH"},
        ]
        
        roles = []
        for config in role_configs[:self.num_roles]:
            role = {
                "id": f"role-{uuid.uuid4().hex[:8]}",
                "name": config["name"],
                "namespace": "default" if config["scope"] == "namespace" else None,
                "type": "ClusterRole" if config["scope"] == "cluster" else "Role",
                "permissions": config["permissions"],
                "risk_level": config["risk"],
                "created": (datetime.now() - timedelta(days=random.randint(60, 365))).isoformat(),
            }
            roles.append(role)
        
        return roles
    
    def _generate_secrets(self) -> List[Dict[str, Any]]:
        """Generate mock secret data"""
        secret_configs = [
            {"name": "prod-db-creds", "sensitivity": "CRITICAL", "contains": "database passwords"},
            {"name": "api-keys", "sensitivity": "HIGH", "contains": "third-party API keys"},
            {"name": "tls-certs", "sensitivity": "HIGH", "contains": "TLS certificates"},
            {"name": "aws-credentials", "sensitivity": "CRITICAL", "contains": "cloud provider credentials"},
            {"name": "jwt-secret", "sensitivity": "HIGH", "contains": "JWT signing keys"},
            {"name": "encryption-keys", "sensitivity": "CRITICAL", "contains": "data encryption keys"},
            {"name": "oauth-client-secret", "sensitivity": "HIGH", "contains": "OAuth credentials"},
            {"name": "registry-credentials", "sensitivity": "MEDIUM", "contains": "container registry auth"},
            {"name": "webhook-tokens", "sensitivity": "MEDIUM", "contains": "webhook authentication"},
            {"name": "ssh-keys", "sensitivity": "HIGH", "contains": "SSH private keys"},
        ]
        
        secrets = []
        for config in secret_configs[:self.num_secrets]:
            secret = {
                "id": f"secret-{uuid.uuid4().hex[:8]}",
                "name": config["name"],
                "namespace": random.choice(["default", "production", "kube-system"]),
                "type": "Secret",
                "sensitivity": config["sensitivity"],
                "contains": config["contains"],
                "is_crown_jewel": config["sensitivity"] == "CRITICAL",
                "created": (datetime.now() - timedelta(days=random.randint(90, 500))).isoformat(),
            }
            secrets.append(secret)
        
        return secrets
    
    def _generate_role_bindings(self, pods, service_accounts, roles) -> List[Dict[str, Any]]:
        """Generate mock role binding relationships"""
        bindings = []
        
        # Create some high-risk bindings (attack paths)
        # Scenario 1: Internet-facing pod -> admin SA -> cluster-admin role -> secrets
        if pods and service_accounts and roles:
            internet_pods = [p for p in pods if p.get("exposed_to_internet")]
            admin_roles = [r for r in roles if "admin" in r["name"].lower()]
            
            if internet_pods and admin_roles:
                # Bind internet pod to service account
                bindings.append({
                    "id": f"binding-{uuid.uuid4().hex[:8]}",
                    "type": "PodToServiceAccount",
                    "source": internet_pods[0]["id"],
                    "source_name": internet_pods[0]["name"],
                    "target": service_accounts[0]["id"] if service_accounts else None,
                    "target_name": service_accounts[0]["name"] if service_accounts else None,
                })
                
                # Bind service account to high-privilege role
                if admin_roles:
                    bindings.append({
                        "id": f"binding-{uuid.uuid4().hex[:8]}",
                        "type": "ServiceAccountToRole",
                        "source": service_accounts[0]["id"],
                        "source_name": service_accounts[0]["name"],
                        "target": admin_roles[0]["id"],
                        "target_name": admin_roles[0]["name"],
                    })
        
        # Create additional random bindings
        # Pods to ServiceAccounts
        for pod in pods[:min(len(pods), len(service_accounts))]:
            sa = random.choice(service_accounts)
            bindings.append({
                "id": f"binding-{uuid.uuid4().hex[:8]}",
                "type": "PodToServiceAccount",
                "source": pod["id"],
                "source_name": pod["name"],
                "target": sa["id"],
                "target_name": sa["name"],
            })
        
        # ServiceAccounts to Roles
        for sa in service_accounts:
            role = random.choice(roles)
            bindings.append({
                "id": f"binding-{uuid.uuid4().hex[:8]}",
                "type": "ServiceAccountToRole",
                "source": sa["id"],
                "source_name": sa["name"],
                "target": role["id"],
                "target_name": role["name"],
            })
        
        return bindings


def generate_mock_cluster():
    """Convenience function to generate mock cluster data"""
    mock_cluster = MockK8sCluster()
    return mock_cluster.generate_cluster_data()
