"""SecureHeal-AI — Streamlit Dashboard.

Provides the human-in-the-loop approval interface, incident visualization,
and evaluation metrics.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import httpx

# --- Page Configuration ---
st.set_page_config(
    page_title="SecureHeal-AI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom CSS ---
st.markdown("""
<style>
    .stApp { background-color: #0e1117; }
    .status-detected { color: #ff6b6b; font-weight: bold; }
    .status-investigating { color: #ffa726; font-weight: bold; }
    .status-pending_approval { color: #42a5f5; font-weight: bold; }
    .status-approved { color: #66bb6a; font-weight: bold; }
    .status-rejected { color: #ef5350; font-weight: bold; }
    .metric-card {
        background: #1a1d23;
        border: 1px solid #2d3139;
        border-radius: 10px;
        padding: 1.5rem;
        text-align: center;
    }
    div[data-testid="stMetric"] {
        background: #1a1d23;
        border: 1px solid #2d3139;
        border-radius: 10px;
        padding: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# --- Configuration ---
API_URL = "http://localhost:8000"


def api_get(path: str) -> dict | list | None:
    """Make a GET request to the SecureHeal-AI backend."""
    try:
        resp = httpx.get(f"{API_URL}{path}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


def api_post(path: str, data: dict) -> dict | None:
    """Make a POST request to the SecureHeal-AI backend."""
    try:
        resp = httpx.post(f"{API_URL}{path}", json=data, timeout=60)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return None


# --- Sidebar ---
st.sidebar.title("🛡️ SecureHeal-AI")
st.sidebar.markdown("---")

# System status
st.sidebar.subheader("System Status")
health = api_get("/health")
if health:
    st.sidebar.success(f"Backend: Online (v{health.get('version', '?')})")
else:
    st.sidebar.error("Backend: Offline")

st.sidebar.markdown("---")

# Navigation
page = st.sidebar.radio(
    "Navigate",
    ["🏠 Incident Overview", "🔍 Investigation Details", "🔧 Patch Review", "📊 Metrics", "📋 Audit Log"],
)

# Demo incident selector
st.sidebar.markdown("---")
st.sidebar.subheader("Quick Actions")
if st.sidebar.button("🚀 Run Demo Pipeline"):
    demo_evidence = [
        {
            "source": "log",
            "type": "sql_error",
            "content": {
                "raw_line": "ERROR: syntax error in SQL query: SELECT * FROM users WHERE name = '' OR '1'='1'",
                "file": "app/main.py"
            },
        },
        {
            "source": "source_code",
            "type": "source_file",
            "content": {
                "file_path": "app/main.py",
                "content": 'async def search_users(query: str):\n    sql = f"SELECT * FROM users WHERE name = \'{query}\'"\n    return db.execute(sql)',
                "language": "python",
            },
        },
    ]
    result = api_post("/api/incidents/demo-001/run", {
        "service_name": "python-fastapi-target",
        "language": "python",
        "classification": "sql_injection",
        "evidence": demo_evidence,
    })
    if result:
        st.sidebar.success("Demo pipeline completed!")
        st.rerun()


# ============================================================
# TAB 1: Incident Overview
# ============================================================
if page == "🏠 Incident Overview":
    st.title("🏠 Incident Overview")

    data = api_get("/api/incidents")
    incidents = data.get("incidents", []) if data else []

    if not incidents:
        st.info("No incidents yet. Click **Run Demo Pipeline** in the sidebar to start.")
        # Show sample data
        st.markdown("### Sample Incident Data (Preview)")
        sample_incidents = [
            {"incident_id": "INC-001", "service_name": "python-fastapi", "classification": "sql_injection", "status": "pending_approval", "language": "python"},
            {"incident_id": "INC-002", "service_name": "java-spring", "classification": "xss", "status": "investigating", "language": "java"},
            {"incident_id": "INC-003", "service_name": "python-fastapi", "classification": "missing_auth", "status": "approved", "language": "python"},
        ]
        for inc in sample_incidents:
            status_color = {"pending_approval": "🔵", "investigating": "🟡", "approved": "🟢", "rejected": "🔴", "detected": "🔴"}.get(inc["status"], "⚪")
            with st.container(border=True):
                cols = st.columns([1, 3, 2, 2, 1])
                cols[0].write(status_color)
                cols[1].write(f"**{inc['incident_id']}** — {inc['service_name']}")
                cols[2].write(f"`{inc['classification']}`")
                cols[3].write(f"{inc['language'].upper()}")
                cols[4].write(inc["status"])
    else:
        # Filters
        col1, col2, col3 = st.columns(3)
        statuses = list(set(i.get("status", "") for i in incidents))
        languages = list(set(i.get("language", "") for i in incidents))
        classifications = list(set(i.get("classification", "") for i in incidents))

        with col1:
            filter_status = st.multiselect("Filter by Status", statuses, default=statuses)
        with col2:
            filter_lang = st.multiselect("Filter by Language", languages, default=languages)
        with col3:
            filter_class = st.multiselect("Filter by Classification", classifications, default=classifications)

        filtered = [
            i for i in incidents
            if i.get("status") in filter_status
            and i.get("language") in filter_lang
            and i.get("classification") in filter_class
        ]

        for inc in filtered:
            status_emoji = {"pending_approval": "🔵", "investigating": "🟡", "approved": "🟢", "rejected": "🔴", "detected": "🔴", "error": "⛔"}.get(inc.get("status", ""), "⚪")
            with st.container(border=True):
                cols = st.columns([1, 3, 2, 2, 2])
                cols[0].write(status_emoji)
                cols[1].write(f"**{inc.get('incident_id', 'N/A')}** — {inc.get('service_name', 'N/A')}")
                cols[2].write(f"`{inc.get('classification', 'N/A')}`")
                cols[3].write(inc.get("language", "N/A").upper())
                cols[4].write(inc.get("status", "N/A"))


# ============================================================
# TAB 2: Investigation Details
# ============================================================
elif page == "🔍 Investigation Details":
    st.title("🔍 Investigation Details")

    incident_id = st.text_input("Enter Incident ID", value="demo-001")

    if incident_id:
        data = api_get(f"/api/incidents/{incident_id}")

        if data and "pipeline_result" in data:
            result = data["pipeline_result"]

            # Evidence Timeline
            st.subheader("📦 Evidence Timeline")
            evidence = result.get("evidence", [])
            if evidence:
                for i, ev in enumerate(evidence):
                    with st.expander(f"Evidence #{i+1}: {ev.get('source', 'N/A')} — {ev.get('type', 'N/A')}"):
                        st.json(ev.get("content", {}))
            else:
                st.info("No evidence collected.")

            # Threat Detection
            st.subheader("🚨 Threat Detection Results")
            threat = result.get("threat_report")
            if threat:
                cols = st.columns(4)
                cols[0].metric("Threat Type", threat.get("threat_type", "N/A"))
                cols[1].metric("CWE", threat.get("cwe_id", "N/A"))
                cols[2].metric("Severity", threat.get("severity", "N/A"))
                cols[3].metric("Endpoints", len(threat.get("affected_endpoints", [])))
                with st.expander("Full Threat Report"):
                    st.json(threat)
            else:
                st.warning("No threats detected.")

            # Root Cause
            st.subheader("🔬 Root Cause Hypothesis")
            rca = result.get("root_cause")
            if rca:
                st.markdown(f"**Hypothesis:** {rca.get('hypothesis', 'N/A')}")
                st.progress(rca.get("confidence", 0), text=f"Confidence: {rca.get('confidence', 0):.0%}")
                if rca.get("causal_chain"):
                    st.markdown("**Causal Chain:**")
                    for step in rca["causal_chain"]:
                        st.markdown(f"  → {step}")
                if rca.get("alternative_explanations"):
                    with st.expander("Alternative Explanations"):
                        for alt in rca["alternative_explanations"]:
                            st.markdown(f"- {alt}")
            else:
                st.info("Root cause analysis not available.")

            # Context Map
            st.subheader("🗺️ Context Map")
            ctx = result.get("context_map")
            if ctx:
                with st.expander("Affected Files & Functions"):
                    st.json(ctx.get("affected_files", []))
                with st.expander("API Endpoint Map"):
                    st.json(ctx.get("api_endpoint_map", {}))
                with st.expander("Dependency Analysis"):
                    st.json(ctx.get("dependency_analysis", []))
        else:
            st.warning("Incident not found or pipeline not yet run. Try running the demo pipeline first.")


# ============================================================
# TAB 3: Patch Review & Approval
# ============================================================
elif page == "🔧 Patch Review":
    st.title("🔧 Patch Review & Approval")

    incident_id = st.text_input("Enter Incident ID", value="demo-001", key="patch_review_id")
    data = api_get(f"/api/incidents/{incident_id}")

    if data and "pipeline_result" in data:
        result = data["pipeline_result"]
        patches = result.get("candidate_patches", [])
        verification = result.get("verification_results", [])
        approved = result.get("approved_patch")

        if not patches:
            st.info("No candidate patches available.")
        else:
            for i, patch in enumerate(patches):
                st.subheader(f"Candidate Patch #{i+1}")

                # Verification badges
                ver = verification[i] if i < len(verification) else {}
                badge_cols = st.columns(3)
                badge_cols[0].metric("Functional", "✅ PASS" if ver.get("functional_pass") else "❌ FAIL")
                badge_cols[1].metric("Security", "✅ PASS" if ver.get("security_pass") else "❌ FAIL")
                badge_cols[2].metric("Regression", "✅ PASS" if ver.get("regression_pass") else "❌ FAIL")

                # Diff view
                col_left, col_right = st.columns(2)
                with col_left:
                    st.markdown("**Original Code:**")
                    st.code(patch.get("original_code", "N/A"), language="python")
                with col_right:
                    st.markdown("**Patched Code:**")
                    st.code(patch.get("patched_code", "N/A"), language="python")

                if patch.get("diff"):
                    with st.expander("View Unified Diff"):
                        st.code(patch["diff"], language="diff")

                st.markdown(f"**Explanation:** {patch.get('explanation', 'N/A')}")
                st.markdown("---")

            # Governance package
            if approved:
                st.subheader("📋 Governance Package")
                gov = approved.get("governance", {})

                risk = gov.get("risk_summary", {})
                risk_color = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(risk.get("risk_level", ""), "⚪")
                st.markdown(f"**Risk Level:** {risk_color} {risk.get('risk_level', 'N/A').upper()}")

                if gov.get("deployment_recommendation"):
                    with st.expander("Deployment Strategy"):
                        st.json(gov["deployment_recommendation"])

                if gov.get("rollback_plan"):
                    with st.expander("Rollback Plan"):
                        st.json(gov["rollback_plan"])

            # Approval buttons
            st.markdown("---")
            st.subheader("🔐 Human Approval Gate")
            col_approve, col_reject = st.columns(2)

            with col_approve:
                if st.button("✅ APPROVE PATCH", type="primary", use_container_width=True):
                    resp = api_post(f"/api/patches/{incident_id}/approve", {
                        "reviewer": "dashboard_user",
                        "decision": "approved",
                        "reason": "Verified via dashboard review",
                    })
                    if resp:
                        st.success("Patch APPROVED! Staged deployment initiated.")

            with col_reject:
                reject_reason = st.text_input("Rejection reason", key="reject_reason")
                if st.button("❌ REJECT PATCH", type="secondary", use_container_width=True):
                    resp = api_post(f"/api/patches/{incident_id}/reject", {
                        "reviewer": "dashboard_user",
                        "decision": "rejected",
                        "reason": reject_reason or "Rejected via dashboard",
                    })
                    if resp:
                        st.warning("Patch REJECTED. Returning to investigation.")
    else:
        st.info("No data available. Run the pipeline for an incident first.")


# ============================================================
# TAB 4: Metrics Dashboard
# ============================================================
elif page == "📊 Metrics":
    st.title("📊 Evaluation Metrics")

    metrics = api_get("/api/metrics")

    if metrics:
        # Top-level KPIs
        cols = st.columns(4)
        cols[0].metric("Total Incidents", metrics.get("total_incidents", 0))
        cols[1].metric("Completed", metrics.get("completed_investigations", 0))
        cols[2].metric("Approved Patches", metrics.get("approved_patches", 0))
        cols[3].metric("Repair Success Rate", f"{metrics.get('repair_success_rate', 0):.0%}")

    # Sample charts (would use real data in production)
    st.subheader("Detection Performance")
    col1, col2 = st.columns(2)

    with col1:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=92,
            title={"text": "Detection Precision (%)"},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": "#42a5f5"},
                   "steps": [{"range": [0, 60], "color": "#ef5350"}, {"range": [60, 80], "color": "#ffa726"}, {"range": [80, 100], "color": "#66bb6a"}]},
        ))
        fig.update_layout(height=300, paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=88,
            title={"text": "Detection Recall (%)"},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": "#42a5f5"},
                   "steps": [{"range": [0, 60], "color": "#ef5350"}, {"range": [60, 80], "color": "#ffa726"}, {"range": [80, 100], "color": "#66bb6a"}]},
        ))
        fig.update_layout(height=300, paper_bgcolor="#0e1117", font_color="white")
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Repair Metrics Over Time")
    # Sample time-series data
    import pandas as pd
    dates = pd.date_range(start="2026-01-01", periods=12, freq="ME")
    df = pd.DataFrame({
        "Date": dates,
        "Repair Success Rate": [0.55, 0.60, 0.63, 0.68, 0.72, 0.75, 0.73, 0.78, 0.82, 0.85, 0.87, 0.89],
        "Security Regression Rate": [0.15, 0.12, 0.10, 0.08, 0.07, 0.06, 0.05, 0.04, 0.04, 0.03, 0.02, 0.02],
    })

    fig = px.line(df, x="Date", y=["Repair Success Rate", "Security Regression Rate"],
                  title="Repair Quality Over Time", markers=True)
    fig.update_layout(paper_bgcolor="#0e1117", plot_bgcolor="#1a1d23", font_color="white", height=400)
    st.plotly_chart(fig, use_container_width=True)

    # MTTR bar chart
    st.subheader("Mean Time to Repair by CWE")
    cwe_data = pd.DataFrame({
        "CWE": ["CWE-89", "CWE-79", "CWE-862", "CWE-918", "CWE-22", "CWE-78", "CWE-502", "CWE-798"],
        "MTTR (minutes)": [12, 8, 15, 18, 10, 20, 14, 5],
    })
    fig = px.bar(cwe_data, x="CWE", y="MTTR (minutes)", title="Mean Time to Repair by Vulnerability Type",
                 color="MTTR (minutes)", color_continuous_scale="RdYlGn_r")
    fig.update_layout(paper_bgcolor="#0e1117", plot_bgcolor="#1a1d23", font_color="white", height=400)
    st.plotly_chart(fig, use_container_width=True)


# ============================================================
# TAB 5: Audit Log
# ============================================================
elif page == "📋 Audit Log":
    st.title("📋 Audit Log")

    incident_id = st.text_input("Enter Incident ID", value="demo-001", key="audit_id")
    data = api_get(f"/api/audit/{incident_id}")

    if data:
        logs = data.get("workflow_log", [])
        if logs:
            for entry in logs:
                with st.container(border=True):
                    cols = st.columns([2, 2, 4, 2])
                    cols[0].write(f"🕐 {entry.get('timestamp', 'N/A')[:19]}")
                    cols[1].write(f"🤖 **{entry.get('agent', 'N/A')}**")
                    cols[2].write(entry.get("action", "N/A"))
                    if entry.get("details"):
                        cols[3].json(entry["details"])

            # Export button
            st.markdown("---")
            log_json = json.dumps(logs, indent=2, default=str)
            st.download_button(
                "📥 Export Audit Log (JSON)",
                data=log_json,
                file_name=f"audit_{incident_id}.json",
                mime="application/json",
            )
        else:
            st.info("No audit entries for this incident.")
    else:
        st.info("Incident not found.")
