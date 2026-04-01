"""Core graph traversal algorithms for security analysis"""
import networkx as nx
from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict

class SecurityAlgorithms:
    """Collection of graph algorithms for security analysis"""
    
    def __init__(self, graph: nx.DiGraph, node_metadata: Dict[str, Any]):
        self.graph = graph
        self.node_metadata = node_metadata
    
    def blast_radius_bfs(self, start_node: str, max_hops: Optional[int] = None) -> Dict[str, Any]:
        """
        BFS-based blast radius detection.
        Finds all nodes reachable from start_node within max_hops.
        """
        if start_node not in self.graph:
            return {"error": "Start node not found in graph"}
        
        visited = set()
        queue = [(start_node, 0)]  # (node, hop_count)
        reachable_nodes = []
        hop_distribution = defaultdict(list)
        
        while queue:
            current_node, hop_count = queue.pop(0)
            
            if current_node in visited:
                continue
            
            if max_hops is not None and hop_count > max_hops:
                continue
            
            visited.add(current_node)
            
            if current_node != start_node:
                metadata = self.node_metadata.get(current_node, {})
                reachable_nodes.append({
                    "id": current_node,
                    "name": metadata.get("name"),
                    "type": metadata.get("type"),
                    "hops": hop_count,
                    "risk_score": metadata.get("risk_score", 0),
                    "is_crown_jewel": metadata.get("is_crown_jewel", False),
                })
                hop_distribution[hop_count].append(current_node)
            
            # Add neighbors to queue
            for neighbor in self.graph.neighbors(current_node):
                if neighbor not in visited:
                    queue.append((neighbor, hop_count + 1))
        
        # Calculate statistics
        crown_jewels_reached = [n for n in reachable_nodes if n.get("is_crown_jewel")]
        total_risk_score = sum(n.get("risk_score", 0) for n in reachable_nodes)
        
        return {
            "start_node": start_node,
            "start_node_name": self.node_metadata.get(start_node, {}).get("name"),
            "total_reachable": len(reachable_nodes),
            "reachable_nodes": reachable_nodes,
            "hop_distribution": {k: len(v) for k, v in hop_distribution.items()},
            "crown_jewels_reached": crown_jewels_reached,
            "total_risk_score": total_risk_score,
            "severity": self._calculate_severity(len(reachable_nodes), len(crown_jewels_reached)),
        }
    
    def shortest_attack_path_dijkstra(self, source: str, target: str) -> Dict[str, Any]:
        """
        Dijkstra's algorithm to find shortest attack path.
        Uses edge weights (inverse risk) to find the most exploitable path.
        """
        if source not in self.graph or target not in self.graph:
            return {"error": "Source or target node not found", "path": []}
        
        try:
            # Find shortest path using weights
            path = nx.dijkstra_path(self.graph, source, target, weight='weight')
            path_length = nx.dijkstra_path_length(self.graph, source, target, weight='weight')
            
            # Build detailed path information
            path_details = []
            total_risk = 0
            
            for i, node_id in enumerate(path):
                metadata = self.node_metadata.get(node_id, {})
                risk_score = metadata.get("risk_score", 0)
                total_risk += risk_score
                
                step = {
                    "step": i + 1,
                    "node_id": node_id,
                    "name": metadata.get("name"),
                    "type": metadata.get("type"),
                    "risk_score": risk_score,
                }
                
                # Add edge information
                if i < len(path) - 1:
                    next_node = path[i + 1]
                    edge_data = self.graph.get_edge_data(node_id, next_node, {})
                    step["edge_to_next"] = edge_data.get("binding_type", "Unknown")
                
                path_details.append(step)
            
            return {
                "source": source,
                "target": target,
                "path": path,
                "path_length": len(path),
                "weighted_distance": path_length,
                "total_risk_score": total_risk,
                "path_details": path_details,
                "severity": self._classify_path_severity(len(path), total_risk),
            }
        except nx.NetworkXNoPath:
            return {
                "source": source,
                "target": target,
                "path": [],
                "message": "No path exists between source and target",
            }
    
    def detect_circular_permissions_dfs(self) -> List[List[str]]:
        """
        DFS-based detection of circular permission chains.
        Finds cycles that could lead to privilege escalation.
        """
        try:
            cycles = list(nx.simple_cycles(self.graph))
            
            # Enhance cycles with metadata
            detailed_cycles = []
            for cycle in cycles:
                cycle_info = {
                    "nodes": cycle,
                    "length": len(cycle),
                    "node_details": [],
                    "total_risk": 0,
                }
                
                for node_id in cycle:
                    metadata = self.node_metadata.get(node_id, {})
                    cycle_info["node_details"].append({
                        "id": node_id,
                        "name": metadata.get("name"),
                        "type": metadata.get("type"),
                        "risk_score": metadata.get("risk_score", 0),
                    })
                    cycle_info["total_risk"] += metadata.get("risk_score", 0)
                
                cycle_info["severity"] = "HIGH" if cycle_info["total_risk"] > 15 else "MEDIUM"
                detailed_cycles.append(cycle_info)
            
            return detailed_cycles
        except Exception as e:
            return [{"error": str(e)}]
    
    def critical_node_analysis(self) -> List[Dict[str, Any]]:
        """
        What-if simulation to find critical nodes.
        Identifies nodes whose removal breaks the most attack paths.
        """
        critical_nodes = []
        
        # Get all entry points and crown jewels
        entry_points = [n for n, m in self.node_metadata.items() if m.get("is_entry_point")]
        crown_jewels = [n for n, m in self.node_metadata.items() if m.get("is_crown_jewel")]
        
        # Count existing paths
        original_paths = self._count_paths_between_sets(entry_points, crown_jewels)
        
        # Test removing each node
        for node_id in self.graph.nodes():
            if node_id in entry_points or node_id in crown_jewels:
                continue  # Don't remove entry/exit points
            
            # Create temporary graph without this node
            temp_graph = self.graph.copy()
            temp_graph.remove_node(node_id)
            
            # Count paths in modified graph
            paths_after_removal = self._count_paths_in_graph(temp_graph, entry_points, crown_jewels)
            paths_broken = original_paths - paths_after_removal
            
            if paths_broken > 0:
                metadata = self.node_metadata.get(node_id, {})
                critical_nodes.append({
                    "node_id": node_id,
                    "name": metadata.get("name"),
                    "type": metadata.get("type"),
                    "paths_broken": paths_broken,
                    "impact_percentage": (paths_broken / original_paths * 100) if original_paths > 0 else 0,
                    "criticality": "CRITICAL" if paths_broken > 5 else "HIGH" if paths_broken > 2 else "MEDIUM",
                })
        
        # Sort by impact
        critical_nodes.sort(key=lambda x: x["paths_broken"], reverse=True)
        return critical_nodes[:10]  # Top 10 most critical
    
    def find_all_attack_paths(self, max_length: int = 6) -> List[Dict[str, Any]]:
        """
        Find all possible attack paths from entry points to crown jewels.
        Limited by max_length to avoid combinatorial explosion.
        """
        entry_points = [n for n, m in self.node_metadata.items() if m.get("is_entry_point")]
        crown_jewels = [n for n, m in self.node_metadata.items() if m.get("is_crown_jewel")]
        
        all_paths = []
        
        for entry in entry_points:
            for crown in crown_jewels:
                try:
                    # Find all simple paths (no cycles)
                    paths = nx.all_simple_paths(self.graph, entry, crown, cutoff=max_length)
                    
                    for path in paths:
                        if len(path) <= max_length:
                            path_risk = sum(self.node_metadata.get(n, {}).get("risk_score", 0) for n in path)
                            all_paths.append({
                                "path": path,
                                "length": len(path),
                                "entry_point": self.node_metadata.get(entry, {}).get("name"),
                                "crown_jewel": self.node_metadata.get(crown, {}).get("name"),
                                "total_risk": path_risk,
                                "severity": self._classify_path_severity(len(path), path_risk),
                            })
                except nx.NetworkXNoPath:
                    continue
        
        # Sort by risk (highest first)
        all_paths.sort(key=lambda x: x["total_risk"], reverse=True)
        return all_paths
    
    def _count_paths_between_sets(self, sources: List[str], targets: List[str]) -> int:
        """Count total number of paths between two sets of nodes"""
        return self._count_paths_in_graph(self.graph, sources, targets)
    
    def _count_paths_in_graph(self, graph: nx.DiGraph, sources: List[str], targets: List[str]) -> int:
        """Count paths in a given graph"""
        count = 0
        for source in sources:
            if source not in graph:
                continue
            for target in targets:
                if target not in graph:
                    continue
                try:
                    # Count simple paths (max length 6 to avoid explosion)
                    paths = list(nx.all_simple_paths(graph, source, target, cutoff=6))
                    count += len(paths)
                except nx.NetworkXNoPath:
                    continue
        return count
    
    def _calculate_severity(self, reachable_count: int, crown_jewels_count: int) -> str:
        """Calculate severity based on blast radius"""
        if crown_jewels_count > 0:
            return "CRITICAL"
        elif reachable_count > 15:
            return "HIGH"
        elif reachable_count > 8:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _classify_path_severity(self, path_length: int, total_risk: float) -> str:
        """Classify path severity based on length and risk"""
        if total_risk > 30 or (path_length <= 4 and total_risk > 20):
            return "CRITICAL"
        elif total_risk > 20 or path_length <= 4:
            return "HIGH"
        elif total_risk > 10 or path_length <= 6:
            return "MEDIUM"
        else:
            return "LOW"
