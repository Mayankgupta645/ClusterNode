# ClusterNodes - Kubernetes Security Analysis Tool

**Graph-powered Kubernetes RBAC security analysis with AI-driven attack path detection.**

## Overview

ClusterNodes is a comprehensive security analysis tool that:
- Models Kubernetes clusters as directed graphs
- Detects attack paths from compromised Pods to crown jewel resources
- Uses graph algorithms (BFS, DFS, Dijkstra's) for security analysis
- Provides AI-powered remediation recommendations
- Generates detailed PDF security reports

## Features

### ✅ Core Security Analysis
- **Live Cluster Modeling**: DAG construction using NetworkX
- **Attack Path Detection**: Finds all paths from entry points to sensitive resources
- **Blast Radius Analysis**: BFS-based impact calculation
- **Critical Node Identification**: What-if simulation to find chokepoints
- **Circular Permission Detection**: DFS-based cycle detection
- **CVE Vulnerability Scanning**: Integration with CVSS scoring

### ✅ AI-Powered Features
- **Google Gemini Integration**: Natural language security explanations
- **Auto-Fix YAML Generation**: Production-ready RBAC restrictions
- **Security Chat**: Ask questions about your cluster security
- **Executive Summaries**: AI-generated reports for leadership

### ✅ Reporting & Monitoring
- **Kill Chain PDF Reports**: Detailed security analysis with FPDF2
- **Temporal Snapshots**: Track security posture over time
- **Snapshot Comparison**: Detect new attack paths
- **Interactive Visualization**: Graph-based UI with Cytoscape.js

### ✅ CLI Tool
Full-featured command-line interface using Typer framework

## Architecture

```
/app/
├── backend/              # FastAPI backend (Python)
│   ├── core/            # Graph engine, algorithms, K8s mock
│   ├── analysis/        # Attack detection, blast radius
│   ├── ai/              # Gemini client, auto-fix
│   ├── reports/         # PDF generation
│   ├── storage/         # Snapshot management
│   ├── cli/             # CLI tool
│   └── server.py        # FastAPI server
├── frontend/            # React frontend (Vite)
│   └── src/
│       └── App.jsx      # Main application
└── data/
    ├── snapshots/       # Cluster snapshots
    └── reports/         # Generated PDFs
```

## API Endpoints

```
GET  /api/analyze                    - Run comprehensive analysis
GET  /api/graph                      - Get graph data
GET  /api/attack-paths               - List all attack paths
GET  /api/blast-radius/{node_id}     - Calculate blast radius
GET  /api/simulate/{node_id}         - Simulate attack
GET  /api/critical-nodes             - Get critical nodes
GET  /api/circular-permissions       - Detect cycles
GET  /api/cve-scan                   - CVE vulnerabilities
POST /api/fix                        - Generate remediation YAML
POST /api/ai-chat                    - AI security chat
GET  /api/report/pdf                 - Generate PDF report
POST /api/snapshot                   - Create snapshot
GET  /api/snapshots                  - List snapshots
POST /api/diff                       - Compare snapshots
```

## CLI Usage

```bash
# Run comprehensive analysis
python -m backend.cli.main analyze

# View graph statistics
python -m backend.cli.main graph

# Calculate blast radius
python -m backend.cli.main blast-radius <node-id>

# Simulate attack
python -m backend.cli.main simulate <node-id>

# View critical nodes
python -m backend.cli.main critical

# CVE scan
python -m backend.cli.main cve

# Generate PDF report
python -m backend.cli.main report

# Create snapshot
python -m backend.cli.main snapshot

# List snapshots
python -m backend.cli.main snapshots

# Compare snapshots
python -m backend.cli.main diff <snapshot-id-1> <snapshot-id-2>
```

**Version**: 1.0.0  
**Status**: ✅ All backend features implemented
