#!/bin/bash
echo "🧪 ClusterNodes Production Verification"
echo "========================================"
echo ""

PASS=0
FAIL=0

# Test 1: Backend Health
echo "1. Testing backend health..."
RESULT=$(curl -s http://localhost:8001/ | jq -r '.status' 2>/dev/null)
if [ "$RESULT" = "running" ]; then
    echo "   ✅ Backend running"
    FEATURES=$(curl -s http://localhost:8001/ | jq -r '.features | "\(.cve_api) + \(.ai_chat)"' 2>/dev/null)
    echo "   📊 Features: $FEATURES"
    ((PASS++))
else
    echo "   ❌ Backend failed"
    ((FAIL++))
fi

# Test 2: Full Analysis
echo "2. Testing full analysis..."
curl -s http://localhost:8001/api/analyze > /tmp/analysis.json 2>&1
RISK=$(jq -r '.summary.risk_level' /tmp/analysis.json 2>/dev/null)
if [ -n "$RISK" ]; then
    PATHS=$(jq -r '.summary.total_attack_paths' /tmp/analysis.json)
    VULNS=$(jq -r '.summary.vulnerable_pods' /tmp/analysis.json)
    echo "   ✅ Analysis complete"
    echo "   📊 Risk: $RISK | Paths: $PATHS | Vulnerable: $VULNS"
    ((PASS++))
else
    echo "   ❌ Analysis failed"
    ((FAIL++))
fi

# Test 3: CVE Scanning
echo "3. Testing CVE scanning..."
CVE_COUNT=$(curl -s http://localhost:8001/api/cve-scan | jq -r '.vulnerable_pods_count' 2>/dev/null)
if [ -n "$CVE_COUNT" ] && [ "$CVE_COUNT" != "null" ]; then
    CVE_RISK=$(curl -s http://localhost:8001/api/cve-scan | jq -r '.overall_risk' 2>/dev/null)
    echo "   ✅ CVE scan working"
    echo "   📊 Vulnerable pods: $CVE_COUNT | Overall risk: $CVE_RISK"
    ((PASS++))
else
    echo "   ❌ CVE scan failed"
    ((FAIL++))
fi

# Test 4: AI Chat
echo "4. Testing AI chat..."
AI_RESPONSE=$(curl -s -X POST http://localhost:8001/api/ai-chat \
  -H "Content-Type: application/json" \
  -d '{"question": "What is the main security risk?"}' 2>/dev/null)
AI_STATUS=$(echo "$AI_RESPONSE" | jq -r '.status' 2>/dev/null)
if [ "$AI_STATUS" = "success" ]; then
    ANSWER_LEN=$(echo "$AI_RESPONSE" | jq -r '.answer | length' 2>/dev/null)
    echo "   ✅ AI chat working"
    echo "   📊 Response length: $ANSWER_LEN characters"
    ((PASS++))
else
    echo "   ❌ AI chat failed"
    ((FAIL++))
fi

# Test 5: Graph Analysis
echo "5. Testing graph analysis..."
NODES=$(curl -s http://localhost:8001/api/graph | jq -r '.statistics.total_nodes' 2>/dev/null)
if [ -n "$NODES" ] && [ "$NODES" != "null" ]; then
    EDGES=$(curl -s http://localhost:8001/api/graph | jq -r '.statistics.total_edges' 2>/dev/null)
    echo "   ✅ Graph analysis working"
    echo "   📊 Nodes: $NODES | Edges: $EDGES"
    ((PASS++))
else
    echo "   ❌ Graph analysis failed"
    ((FAIL++))
fi

# Test 6: Attack Path Detection
echo "6. Testing attack path detection..."
PATHS=$(curl -s http://localhost:8001/api/attack-paths | jq -r '.total_paths' 2>/dev/null)
if [ -n "$PATHS" ] && [ "$PATHS" != "null" ]; then
    CRITICAL=$(curl -s http://localhost:8001/api/attack-paths | jq -r '.by_severity.critical_count' 2>/dev/null)
    echo "   ✅ Attack paths detected"
    echo "   📊 Total: $PATHS | Critical: $CRITICAL"
    ((PASS++))
else
    echo "   ❌ Attack path detection failed"
    ((FAIL++))
fi

# Test 7: Critical Nodes
echo "7. Testing critical node analysis..."
CRITICAL_NODES=$(curl -s http://localhost:8001/api/critical-nodes | jq -r '.total_critical_nodes' 2>/dev/null)
if [ -n "$CRITICAL_NODES" ] && [ "$CRITICAL_NODES" != "null" ]; then
    echo "   ✅ Critical node analysis working"
    echo "   📊 Critical nodes: $CRITICAL_NODES"
    ((PASS++))
else
    echo "   ❌ Critical node analysis failed"
    ((FAIL++))
fi

# Test 8: PDF Generation
echo "8. Testing PDF generation..."
curl -s http://localhost:8001/api/report/pdf > /tmp/clusternodes_test.pdf 2>&1
if [ -f /tmp/clusternodes_test.pdf ] && [ -s /tmp/clusternodes_test.pdf ]; then
    SIZE=$(stat -c%s /tmp/clusternodes_test.pdf)
    echo "   ✅ PDF generation working"
    echo "   📊 PDF size: $SIZE bytes"
    ((PASS++))
else
    echo "   ❌ PDF generation failed"
    ((FAIL++))
fi

# Test 9: Snapshot System
echo "9. Testing snapshot system..."
SNAPSHOT_ID=$(curl -s -X POST http://localhost:8001/api/snapshot | jq -r '.snapshot_id' 2>/dev/null)
if [ -n "$SNAPSHOT_ID" ] && [ "$SNAPSHOT_ID" != "null" ]; then
    TOTAL_SNAPSHOTS=$(curl -s http://localhost:8001/api/snapshots | jq -r '.total' 2>/dev/null)
    echo "   ✅ Snapshot system working"
    echo "   📊 Latest: $SNAPSHOT_ID | Total: $TOTAL_SNAPSHOTS"
    ((PASS++))
else
    echo "   ❌ Snapshot system failed"
    ((FAIL++))
fi

# Test 10: Auto-Fix YAML
echo "10. Testing auto-fix generation..."
YAML_RESULT=$(curl -s -X POST http://localhost:8001/api/fix \
  -H "Content-Type: application/json" \
  -d '{"issue_type": "overprivileged_sa", "node_data": {"name": "test-sa", "namespace": "default"}}' | jq -r '.status' 2>/dev/null)
if [ "$YAML_RESULT" = "success" ]; then
    echo "   ✅ Auto-fix generation working"
    echo "   📊 YAML generated successfully"
    ((PASS++))
else
    echo "   ❌ Auto-fix generation failed"
    ((FAIL++))
fi

echo ""
echo "========================================"
echo "📊 Test Results:"
echo "   ✅ Passed: $PASS/10"
echo "   ❌ Failed: $FAIL/10"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED!"
    echo "✅ Application is PRODUCTION READY"
    exit 0
else
    echo "⚠️  Some tests failed"
    echo "Review the output above for details"
    exit 1
fi
