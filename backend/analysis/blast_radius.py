"""Blast radius analysis"""
from typing import Dict, List, Any
from core.algorithms import SecurityAlgorithms
from core.graph_engine import KubernetesGraphEngine

class BlastRadiusAnalyzer:
    """Analyzes blast radius for compromised nodes"""
    
    def __init__(self, graph_engine: KubernetesGraphEngine):
        self.graph_engine = graph_engine
        self.algorithms = SecurityAlgorithms(
            graph_engine.graph,
            graph_engine.node_metadata
        )
    
    def analyze_node_blast_radius(self, node_id: str, max_hops: int = None) -> Dict[str, Any]:
        """Analyze blast radius from a specific node"""
        result = self.algorithms.blast_radius_bfs(node_id, max_hops)
        
        if "error" in result:
            return result
        
        # Enhanced analysis
        reachable = result.get("reachable_nodes", [])
        
        # Group by type
        by_type = {}
        for node in reachable:
            node_type = node.get("type", "Unknown")
            if node_type not in by_type:
                by_type[node_type] = []
            by_type[node_type].append(node)
        
        # Group by risk level
        by_risk = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for node in reachable:
            risk = node.get("risk_score", 0)
            if risk >= 9:
                by_risk["CRITICAL"].append(node)
            elif risk >= 7:
                by_risk["HIGH"].append(node)
            elif risk >= 4:
                by_risk["MEDIUM"].append(node)
            else:
                by_risk["LOW"].append(node)
        
        result["breakdown_by_type"] = {k: len(v) for k, v in by_type.items()}
        result["breakdown_by_risk"] = {k: len(v) for k, v in by_risk.items()}
        result["high_risk_nodes"] = by_risk["CRITICAL"] + by_risk["HIGH"]
        
        return result
    
    def compare_blast_radii(self, node_ids: List[str]) -> Dict[str, Any]:
        """Compare blast radii of multiple nodes"""
        comparisons = []
        
        for node_id in node_ids:
            result = self.analyze_node_blast_radius(node_id)
            if "error" not in result:
                comparisons.append({
                    "node_id": node_id,
                    "node_name": result.get("start_node_name"),
                    "total_reachable": result.get("total_reachable"),
                    "crown_jewels_reached": len(result.get("crown_jewels_reached", [])),
                    "severity": result.get("severity"),
                })
        
        # Sort by impact (most dangerous first)
        comparisons.sort(
            key=lambda x: (x["crown_jewels_reached"], x["total_reachable"]),
            reverse=True
        )
        
        return {
            "nodes_analyzed": len(comparisons),
            "comparisons": comparisons,
            "most_dangerous": comparisons[0] if comparisons else None,
        }
