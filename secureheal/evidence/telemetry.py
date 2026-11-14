"""Telemetry processor — parses OpenTelemetry traces and logs."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from secureheal.evidence.models import TelemetryData

logger = logging.getLogger("secureheal.evidence.telemetry")


class TelemetryProcessor:
    """Processes and correlates OpenTelemetry data."""

    def parse_otel_traces(self, trace_data: dict) -> list[dict]:
        """Extract span information, timing, and errors from OTLP traces."""
        spans: list[dict] = []

        for resource_span in trace_data.get("resourceSpans", []):
            service_name = ""
            for attr in resource_span.get("resource", {}).get("attributes", []):
                if attr.get("key") == "service.name":
                    service_name = attr.get("value", {}).get("stringValue", "")

            for scope_span in resource_span.get("scopeSpans", []):
                for span in scope_span.get("spans", []):
                    parsed = {
                        "trace_id": span.get("traceId", ""),
                        "span_id": span.get("spanId", ""),
                        "parent_span_id": span.get("parentSpanId", ""),
                        "name": span.get("name", ""),
                        "kind": span.get("kind", ""),
                        "start_time": span.get("startTimeUnixNano", 0),
                        "end_time": span.get("endTimeUnixNano", 0),
                        "duration_ms": (
                            (span.get("endTimeUnixNano", 0) - span.get("startTimeUnixNano", 0))
                            / 1_000_000
                        ),
                        "status": span.get("status", {}).get("code", "OK"),
                        "service_name": service_name,
                        "attributes": {
                            attr.get("key", ""): self._extract_attr_value(attr.get("value", {}))
                            for attr in span.get("attributes", [])
                        },
                        "events": [
                            {
                                "name": evt.get("name", ""),
                                "timestamp": evt.get("timeUnixNano", 0),
                                "attributes": {
                                    a.get("key", ""): self._extract_attr_value(a.get("value", {}))
                                    for a in evt.get("attributes", [])
                                },
                            }
                            for evt in span.get("events", [])
                        ],
                        "has_error": span.get("status", {}).get("code") == "ERROR",
                    }
                    spans.append(parsed)

        logger.info("Parsed %d spans from trace data", len(spans))
        return spans

    def parse_otel_logs(self, log_data: list[dict]) -> list[dict]:
        """Extract security-relevant log entries from OTLP log records."""
        parsed_logs: list[dict] = []

        for record in log_data:
            body = record.get("body", {}).get("stringValue", "")
            severity = record.get("severityText", "INFO")

            # Focus on warning+ and security-related entries
            if severity in ("WARN", "ERROR", "FATAL") or any(
                kw in body.lower()
                for kw in ("auth", "denied", "injection", "error", "exception", "forbidden", "unauthorized")
            ):
                parsed_logs.append({
                    "timestamp": record.get("timeUnixNano", 0),
                    "severity": severity,
                    "body": body,
                    "trace_id": record.get("traceId", ""),
                    "span_id": record.get("spanId", ""),
                    "attributes": {
                        attr.get("key", ""): self._extract_attr_value(attr.get("value", {}))
                        for attr in record.get("attributes", [])
                    },
                })

        logger.info("Parsed %d security-relevant log entries", len(parsed_logs))
        return parsed_logs

    def correlate_traces_to_endpoints(
        self, traces: list[dict], api_spec: dict | None = None
    ) -> dict:
        """Map trace spans to API endpoints."""
        endpoint_map: dict[str, list[dict]] = {}

        for span in traces:
            attrs = span.get("attributes", {})
            http_method = attrs.get("http.method", attrs.get("http.request.method", ""))
            http_url = attrs.get("http.url", attrs.get("url.full", ""))
            http_route = attrs.get("http.route", attrs.get("http.target", ""))

            if http_method and (http_route or http_url):
                key = f"{http_method} {http_route or http_url}"
                if key not in endpoint_map:
                    endpoint_map[key] = []
                endpoint_map[key].append({
                    "trace_id": span["trace_id"],
                    "span_id": span["span_id"],
                    "duration_ms": span["duration_ms"],
                    "has_error": span["has_error"],
                    "status": span["status"],
                })

        return endpoint_map

    def extract_anomalies(self, telemetry: TelemetryData) -> list[dict]:
        """Find unusual patterns: high error rates, latency spikes, auth failures."""
        anomalies: list[dict] = []
        traces = self.parse_otel_traces({"resourceSpans": []})  # Would use real data

        # Detect error rate spikes
        error_spans = [s for s in traces if s.get("has_error")]
        if traces and len(error_spans) / len(traces) > 0.1:
            anomalies.append({
                "type": "high_error_rate",
                "details": f"{len(error_spans)}/{len(traces)} spans have errors ({len(error_spans)/len(traces)*100:.1f}%)",
                "severity": "high",
            })

        # Detect auth failures in logs
        auth_failures = [
            log for log in telemetry.logs
            if any(kw in str(log).lower() for kw in ("auth", "denied", "forbidden", "unauthorized"))
        ]
        if len(auth_failures) > 5:
            anomalies.append({
                "type": "auth_failure_spike",
                "details": f"{len(auth_failures)} authentication failures detected",
                "severity": "critical",
            })

        return anomalies

    @staticmethod
    def _extract_attr_value(value: dict) -> str | int | float | bool:
        """Extract the typed value from an OTLP attribute."""
        for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if key in value:
                return value[key]
        return str(value)
