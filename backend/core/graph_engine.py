"""Core graph engine using NetworkX for DAG construction and analysis"""
import networkx as nx
from typing import Dict, List, Any, Tuple, Optional
import json
from datetime import datetime

class KubernetesGraphEngine:
    """Builds and manages Kubernetes permission graph as DAG"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.node_metadata = {}
        self.edge_metadata = {}
        
    def build_graph_from_cluster_data(self, cluster_data: Dict[str, Any]) -> nx.DiGraph:
        """Build NetworkX DAG from Kubernetes cluster data"""
        self.graph.clear()
        self.node_metadata.clear()
        self.edge_metadata.clear()
        
        # Add all nodes
        self._add_pod_nodes(cluster_data.get("pods", []))
        self._add_service_account_nodes(cluster_data.get("service_accounts", []))
        self._add_role_nodes(cluster_data.get("roles", []))
        self._add_secret_nodes(cluster_data.get("secrets", []))
        
        # Add edges based on role bindings
        self._add_edges_from_bindings(cluster_data.get("role_bindings", []))
        
        # Add edges from roles to secrets (implicit permission)
        self._add_role_to_secret_edges(cluster_data)
        
        return self.graph
    
    def _add_pod_nodes(self, pods: List[Dict]):
        """Add pod nodes to graph"""
        for pod in pods:
            node_id = pod["id"]
            self.graph.add_node(node_id)
            
            # Calculate risk score for pod
            risk_score = 0.0
            if pod.get("exposed_to_internet"):
                risk_score += 5.0
            if pod.get("is_privileged"):
                risk_score += 3.0
            if pod.get("cve"):
                cvss = pod["cve"].get("cvss_score", 0)
                risk_score += cvss
            
            self.node_metadata[node_id] = {
                "name": pod["name"],
                "type": "Pod",
                "namespace": pod.get("namespace"),
                "image": pod.get("image"),
                "exposed_to_internet": pod.get("exposed_to_internet", False),
                "is_privileged": pod.get("is_privileged", False),
                "cve": pod.get("cve"),
                "risk_score": risk_score,
                "is_entry_point": pod.get("exposed_to_internet", False),
            }
            
            # Set node attributes
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
    
    def _add_service_account_nodes(self, service_accounts: List[Dict]):
        """Add service account nodes to graph"""
        for sa in service_accounts:
            node_id = sa["id"]
            self.graph.add_node(node_id)
            
            self.node_metadata[node_id] = {
                "name": sa["name"],
                "type": "ServiceAccount",
                "namespace": sa.get("namespace"),
                "auto_mount_token": sa.get("auto_mount_token", True),
                "risk_score": 2.0 if sa.get("auto_mount_token") else 1.0,
            }
            
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
    
    def _add_role_nodes(self, roles: List[Dict]):
        """Add role nodes to graph"""
        for role in roles:
            node_id = role["id"]
            self.graph.add_node(node_id)
            
            # Risk scoring based on permissions
            risk_map = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0}
            risk_score = risk_map.get(role.get("risk_level", "LOW"), 1.0)
            
            self.node_metadata[node_id] = {
                "name": role["name"],
                "type": role["type"],
                "namespace": role.get("namespace"),
                "permissions": role.get("permissions", []),
                "risk_level": role.get("risk_level"),
                "risk_score": risk_score,
                "is_cluster_scope": role["type"] == "ClusterRole",
            }
            
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
    
    def _add_secret_nodes(self, secrets: List[Dict]):
        """Add secret nodes to graph"""
        for secret in secrets:
            node_id = secret["id"]
            self.graph.add_node(node_id)
            
            # High risk for crown jewels
            risk_map = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0}
            risk_score = risk_map.get(secret.get("sensitivity", "LOW"), 1.0)
            
            self.node_metadata[node_id] = {
                "name": secret["name"],
                "type": "Secret",
                "namespace": secret.get("namespace"),
                "sensitivity": secret.get("sensitivity"),
                "is_crown_jewel": secret.get("is_crown_jewel", False),
                "contains": secret.get("contains"),
                "risk_score": risk_score,
            }
            
            nx.set_node_attributes(self.graph, {node_id: self.node_metadata[node_id]})
    
    def _add_edges_from_bindings(self, bindings: List[Dict]):
        """Add edges based on role bindings"""
        for binding in bindings:
            source = binding.get("source")
            target = binding.get("target")
            
            if source and target and source in self.graph and target in self.graph:
                # Weight is inverse risk (lower is riskier)
                source_risk = self.node_metadata.get(source, {}).get("risk_score", 1.0)
                target_risk = self.node_metadata.get(target, {}).get("risk_score", 1.0)
                weight = 1.0 / (source_risk + target_risk + 1.0)  # Avoid division by zero
                
                self.graph.add_edge(source, target, weight=weight, binding_type=binding.get("type"))
    
    def _add_role_to_secret_edges(self, cluster_data: Dict):
        """Add edges from roles with secret permissions to secrets"""
        roles = cluster_data.get("roles", [])
        secrets = cluster_data.get("secrets", [])
        
        for role in roles:
            role_id = role["id"]
            permissions = role.get("permissions", [])
            
            # Check if role has secret access permissions
            has_secret_access = any(
                "secrets" in perm or "*" in perm 
                for perm in permissions
            )
            
            if has_secret_access and role_id in self.graph:
                for secret in secrets:
                    secret_id = secret["id"]
                    if secret_id in self.graph:
                        # Add edge with weight based on sensitivity
                        secret_risk = self.node_metadata.get(secret_id, {}).get("risk_score", 1.0)
                        weight = 1.0 / (secret_risk + 1.0)
                        
                        self.graph.add_edge(role_id, secret_id, weight=weight, binding_type="RoleToSecret")
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get statistics about the graph"""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "is_dag": nx.is_directed_acyclic_graph(self.graph),
            "density": nx.density(self.graph),
            "nodes_by_type": self._count_nodes_by_type(),
            "crown_jewels": self._get_crown_jewels(),
            "entry_points": self._get_entry_points(),
        }
    
    def _count_nodes_by_type(self) -> Dict[str, int]:
        """Count nodes by type"""
        type_counts = {}
        for node_id, metadata in self.node_metadata.items():
            node_type = metadata.get("type", "Unknown")
            type_counts[node_type] = type_counts.get(node_type, 0) + 1
        return type_counts
    
    def _get_crown_jewels(self) -> List[Dict]:
        """Get list of crown jewel nodes (high-value targets)"""
        crown_jewels = []
        for node_id, metadata in self.node_metadata.items():
            if metadata.get("is_crown_jewel") or metadata.get("risk_score", 0) >= 9.0:
                crown_jewels.append({
                    "id": node_id,
                    "name": metadata.get("name"),
                    "type": metadata.get("type"),
                    "risk_score": metadata.get("risk_score"),
                })
        return crown_jewels
    
    def _get_entry_points(self) -> List[Dict]:
        """Get list of potential entry points (internet-facing)"""
        entry_points = []
        for node_id, metadata in self.node_metadata.items():
            if metadata.get("is_entry_point") or metadata.get("exposed_to_internet"):
                entry_points.append({
                    "id": node_id,
                    "name": metadata.get("name"),
                    "type": metadata.get("type"),
                    "cve": metadata.get("cve"),
                })
        return entry_points
    
    def export_for_visualization(self) -> Dict[str, Any]:
        """Export graph data for frontend visualization"""
        nodes = []
        edges = []
        
        for node_id in self.graph.nodes():
            metadata = self.node_metadata.get(node_id, {})
            nodes.append({
                "id": node_id,
                "label": metadata.get("name", node_id),
                "type": metadata.get("type", "Unknown"),
                "risk_score": metadata.get("risk_score", 0),
                **metadata
            })
        
        for source, target, data in self.graph.edges(data=True):
            edges.append({
                "source": source,
                "target": target,
                "weight": data.get("weight", 1.0),
                "type": data.get("binding_type", "Unknown"),
            })
        
        return {"nodes": nodes, "edges": edges}
