# SecureHeal-AI

> An Attack-Context-Aware Multi-Agent Framework for Causal Root-Cause Analysis, Security-Constrained Automated Program Repair and Human-Verified Self-Healing of Cloud-Native Applications and APIs

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Central Orchestrator (LangGraph)              │
│              Typed shared state · Audit trail · Workflow control │
├──────────┬──────────┬───────────┬──────────┬──────────┬─────────┤
│ Agent 1  │ Agent 2  │ Agent 3   │ Agent 4  │ Agent 5  │ Agent 6 │
│ Threat   │ Root     │ Context   │ Repair   │ Patch    │Recovery │
│Detection │ Cause    │Intelligence│Generation│Verification│Govern.│
└──────────┴──────────┴───────────┴──────────┴──────────┴─────────┘
                              ▼
                    ┌───────────────────┐
                    │ Human Approval    │
                    │ Gate (Streamlit)  │
                    └───────────────────┘
```

**Pipeline flow:** Evidence Collection → Threat Detection → Root-Cause Analysis → Context Intelligence → Repair Generation → Patch Verification → Governance Review → Human Approval

## 🎯 Target Vulnerability Classes

| CWE | Vulnerability | Focus |
|-----|--------------|-------|
| CWE-89 | SQL Injection | Input handling & query safety |
| CWE-79 | Cross-Site Scripting | Output encoding |
| CWE-862 | Missing Authorization | Access-control enforcement |
| CWE-918 | Server-Side Request Forgery | URL validation |
| CWE-22 | Path Traversal | File path boundaries |
| CWE-78 | OS Command Injection | Safe command handling |
| CWE-502 | Insecure Deserialization | Trust boundaries |
| CWE-798 | Hardcoded Credentials | Secret management |

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| AI Orchestration | Python, LangGraph |
| Target Services | Java Spring Boot, Python FastAPI |
| Code Analysis | Tree-sitter, Semgrep |
| API Security | OWASP ZAP |
| Telemetry | OpenTelemetry |
| Knowledge Store | ChromaDB |
| Backend API | FastAPI, PostgreSQL |
| Dashboard | Streamlit, Plotly |
| Isolation | Docker Compose |
| Testing | Pytest, JUnit |

## 🚀 Quick Start

### Prerequisites
- Python ≥ 3.11
- Docker & Docker Compose
- An LLM API key (Google Gemini or OpenAI)

### Setup

```bash
# 1. Clone and enter the project
cd SecureHeal-AI

# 2. Create environment file
cp .env.example .env
# Edit .env and set your GOOGLE_API_KEY or OPENAI_API_KEY

# 3. Start all services with Docker
docker compose up --build

# 4. Access the dashboard
# Backend API: http://localhost:8000
# Dashboard:   http://localhost:8501
```

### Local Development (without Docker)

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -e ".[dev]"

# Run the backend
uvicorn secureheal.main:app --reload --port 8000

# Run the dashboard (separate terminal)
streamlit run secureheal/dashboard/app.py
```

## 📁 Project Structure

```
SecureHeal-AI/
├── secureheal/                  # Core framework
│   ├── orchestrator/            # LangGraph pipeline & shared state
│   ├── agents/                  # 6 specialized agents
│   ├── evidence/                # Evidence collection & telemetry
│   ├── analysis/                # Causal analysis & correlation
│   ├── repair/                  # Patch generation & constraints
│   ├── verification/            # Functional & security verification
│   ├── governance/              # Approval gateway & rollback
│   ├── knowledge/               # ChromaDB vector store
│   ├── dashboard/               # Streamlit UI
│   ├── api/                     # REST API endpoints
│   └── db/                      # Database models & session
├── target_services/             # Intentionally vulnerable test targets
│   ├── python_fastapi/          # Python FastAPI service (8 CWEs)
│   └── java_spring_boot/        # Java Spring Boot service (8 CWEs)
├── vulnerability_cases/         # Curated test cases & sample evidence
├── tests/                       # Unit and integration tests
├── docker-compose.yml
└── pyproject.toml
```

## 📊 Evaluation Metrics

- **Detection precision / recall** — how accurately threats are identified
- **Root-cause accuracy** — correct component identification rate
- **Repair success rate** — valid patches under acceptance policy
- **Security regression rate** — new weaknesses introduced by patches
- **Mean time to repair (MTTR)** — incident-to-verified-patch duration
- **Computational cost** — tokens, tool time, and cost per repair

## ⚖️ Research Ethics

- All testing is performed in **isolated Docker environments**
- Vulnerable applications are **clearly marked** and must **never** be deployed
- **Human approval** is mandatory before any patch reaches production
- LLM-generated explanations are **not treated as proof** — tool output and test evidence are required

## 📄 License

MIT — Research use only. See the research proposal for full details.
