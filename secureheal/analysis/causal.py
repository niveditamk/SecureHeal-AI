"""Causal analysis — builds evidence graphs and generates hypotheses."""

from __future__ import annotations

import logging
from datetime import datetime

from secureheal.evidence.models import EvidenceItem

logger = logging.getLogger("secureheal.analysis")


class CausalAnalyzer:
    """Builds evidence relationships and generates causal hypotheses."""

    def build_evidence_graph(self, evidence_items: list[EvidenceItem]) -> dict:
        """Create a directed graph of evidence relationships.

        Nodes are evidence items; edges represent temporal, spatial, or causal links.
        """
        nodes = []
        edges = []

        for item in evidence_items:
            nodes.append({
                "id": item.id,
                "source": item.source.value,
                "type": item.type,
                "severity": item.severity,
                "timestamp": item.timestamp.isoformat() if isinstance(item.timestamp, datetime) else str(item.timestamp),
            })

        # Temporal edges: items close in time from the same service
        sorted_items = sorted(evidence_items, key=lambda e: e.timestamp)
        for i in range(len(sorted_items) - 1):
            a, b = sorted_items[i], sorted_items[i + 1]
            delta = abs((b.timestamp - a.timestamp).total_seconds())
            if delta < 60:  # Within 1 minute
                edges.append({
                    "from": a.id,
                    "to": b.id,
                    "relation": "temporal_proximity",
                    "weight": max(0, 1 - delta / 60),
                })

        # Spatial edges: items referencing the same file or endpoint
        file_groups: dict[str, list[str]] = {}
        for item in evidence_items:
            file_ref = item.content.get("file") or item.content.get("file_path") or ""
            if file_ref:
                file_groups.setdefault(file_ref, []).append(item.id)

        for file_ref, ids in file_groups.items():
            for i, id_a in enumerate(ids):
                for id_b in ids[i + 1 :]:
                    edges.append({
                        "from": id_a,
                        "to": id_b,
                        "relation": "same_file",
                        "context": file_ref,
                    })

        return {"nodes": nodes, "edges": edges}

    def generate_hypotheses(
        self, evidence_graph: dict, threat_report: dict
    ) -> list[dict]:
        """Produce ranked causal hypotheses with confidence scores."""
        hypotheses: list[dict] = []

        # Primary hypothesis from the threat report
        cwe_id = threat_report.get("cwe_id", "unknown")
        threat_type = threat_report.get("threat_type", "unknown")

        primary = {
            "hypothesis": f"The {threat_type} vulnerability ({cwe_id}) is the root cause of the incident",
            "confidence": 0.7,
            "supporting_nodes": [
                n["id"] for n in evidence_graph.get("nodes", [])
                if n.get("severity") in ("critical", "high")
            ],
            "causal_chain": [
                "Attacker sends malicious input to vulnerable endpoint",
                f"Application processes input without proper {threat_type.lower()} protection",
                "Vulnerability is exploited, leading to security incident",
            ],
        }
        hypotheses.append(primary)

        # Check for dependency-related hypothesis
        dep_nodes = [
            n for n in evidence_graph.get("nodes", []) if n.get("source") == "dependency"
        ]
        if dep_nodes:
            hypotheses.append({
                "hypothesis": "A vulnerable third-party dependency contributed to or enabled the exploit",
                "confidence": 0.3,
                "supporting_nodes": [n["id"] for n in dep_nodes],
                "causal_chain": [
                    "Third-party dependency contains a known vulnerability",
                    "Application code uses the vulnerable component",
                    "Attacker exploits the dependency vulnerability",
                ],
            })

        # Configuration-related hypothesis
        hypotheses.append({
            "hypothesis": "Misconfiguration (missing security headers, disabled auth) enabled the attack",
            "confidence": 0.2,
            "supporting_nodes": [],
            "causal_chain": [
                "Security configuration is missing or misconfigured",
                "Attack bypasses expected security controls",
            ],
        })

        # Sort by confidence
        hypotheses.sort(key=lambda h: h["confidence"], reverse=True)
        return hypotheses

    def evaluate_hypothesis(
        self, hypothesis: dict, evidence_items: list[EvidenceItem]
    ) -> dict:
        """Check if evidence supports or contradicts a hypothesis."""
        supporting = 0
        contradicting = 0
        neutral = 0

        for item in evidence_items:
            if item.id in hypothesis.get("supporting_nodes", []):
                supporting += 1
            elif item.severity in ("critical", "high"):
                neutral += 1  # High-severity items not linked = uncertain
            else:
                neutral += 1

        total = supporting + contradicting + neutral
        support_ratio = supporting / total if total > 0 else 0

        return {
            "hypothesis": hypothesis["hypothesis"],
            "original_confidence": hypothesis["confidence"],
            "adjusted_confidence": min(1.0, hypothesis["confidence"] * (1 + support_ratio)),
            "supporting_count": supporting,
            "contradicting_count": contradicting,
            "neutral_count": neutral,
            "verdict": "supported" if support_ratio > 0.3 else "weak" if support_ratio > 0.1 else "unsupported",
        }

    def select_best_hypothesis(self, hypotheses: list[dict]) -> dict:
        """Return the most supported hypothesis with alternatives."""
        if not hypotheses:
            return {
                "hypothesis": "No hypothesis could be formed",
                "confidence": 0,
                "alternatives": [],
            }

        best = hypotheses[0]
        return {
            **best,
            "alternatives": [
                {"hypothesis": h["hypothesis"], "confidence": h["confidence"]}
                for h in hypotheses[1:]
            ],
        }
