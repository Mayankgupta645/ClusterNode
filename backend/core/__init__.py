"""
Kubernetes Security Graph Analyzer
===================================
Core modules:
    graph_engine   – builds the NetworkX permission graph
    algorithms     – BFS / Dijkstra / DFS analysis on the graph
    cve_scoring    – CVE lookup (NIST NVD + fallback mock data)
    k8s_client     – LIVE Kubernetes API data (production use)
    k8s_mock       – mock cluster data generator (testing / demo)
"""

from graph_engine import KubernetesGraphEngine
from algorithms   import SecurityAlgorithms
from cve_scoring  import CVEScorer

# Live API (requires `pip install kubernetes` and cluster access)
from k8s_client import K8sClient, generate_live_cluster

# Mock data (no cluster needed — for testing / CI)
from k8s_mock import MockK8sCluster, generate_mock_cluster

__all__ = [
    # Graph + analysis
    "KubernetesGraphEngine",
    "SecurityAlgorithms",
    "CVEScorer",
    # Data sources
    "K8sClient",
    "generate_live_cluster",
    "MockK8sCluster",
    "generate_mock_cluster",
]