"""Critical node identification"""
from typing import Dict, List, Any
from core.algorithms import SecurityAlgorithms
from core.graph_engine import KubernetesGraphEngine

class CriticalNodeAnalyzer:
    """Identifies critical nodes in the security graph"""
    
    def __init__(self, graph_engine: KubernetesGraphEngine):
        self.graph_engine = graph_engine
        self.algorithms = SecurityAlgorithms(
            graph_engine.graph,
            graph_engine.node_metadata
        )
    
    def identify_critical_nodes(self) -> Dict[str, Any]:
        """Identify nodes critical to attack paths"""
        critical_nodes = self.algorithms.critical_node_analysis()
        
        return {
            "total_critical_nodes": len(critical_nodes),
            "critical_nodes": critical_nodes,
            "top_5_most_critical": critical_nodes[:5],
            "remediation_priority": self._generate_remediation_priority(critical_nodes),
        }
    
    def _generate_remediation_priority(self, critical_nodes: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation list"""
        priority_list = []
        
        for i, node in enumerate(critical_nodes[:10], 1):
            priority_list.append({
                "priority": i,
                "node_name": node.get("name"),
                "node_type": node.get("type"),
                "impact": node.get("criticality"),
                "paths_affected": node.get("paths_broken"),
                "recommended_action": self._get_recommended_action(node),
            })
        
        return priority_list
    
    def _get_recommended_action(self, node: Dict) -> str:
        """Get recommended remediation action"""
        node_type = node.get("type")
        
        if node_type == "ServiceAccount":
            return f"Restrict permissions for {node.get('name')} - remove unnecessary RBAC bindings"
        elif node_type in ["Role", "ClusterRole"]:
            return f"Reduce scope of {node.get('name')} - apply principle of least privilege"
        elif node_type == "Pod":
            return f"Isolate {node.get('name')} with Network Policies or move to separate namespace"
        else:
            return f"Review and restrict access to {node.get('name')}"
    
    def analyze_circular_permissions(self) -> Dict[str, Any]:
        """Analyze circular permission chains"""
        cycles = self.algorithms.detect_circular_permissions_dfs()
        
        if cycles and "error" in cycles[0]:
            return {"cycles_found": 0, "cycles": [], "error": cycles[0].get("error")}
        
        return {
            "cycles_found": len(cycles),
            "cycles": cycles,
            "high_risk_cycles": [c for c in cycles if c.get("severity") == "HIGH"],
            "recommendations": self._generate_cycle_recommendations(cycles),
        }
    
    def _generate_cycle_recommendations(self, cycles: List[Dict]) -> List[str]:
        """Generate recommendations for breaking cycles"""
        if not cycles:
            return ["No circular permissions detected - good security posture"]
        
        recommendations = [
            f"Found {len(cycles)} circular permission chain(s) - these create privilege escalation risks",
        ]
        
        for i, cycle in enumerate(cycles[:5], 1):
            cycle_names = [n.get("name") for n in cycle.get("node_details", [])]
            recommendations.append(
                f"Cycle {i}: {' -> '.join(cycle_names)} -> {cycle_names[0] if cycle_names else ''} "
                f"(break by removing one RBAC binding)"
            )
        
        return recommendations
