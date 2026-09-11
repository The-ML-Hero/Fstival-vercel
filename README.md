# API Guardian - Complete Platform (Modules 1, 2, 3 & Frontend UI)

**AI-Powered API Security Attack Simulation, Bruno Automated Execution, Fix Verification & Continuous Governance Platform**

API Guardian is an end-to-end API security testing, attack simulation, and risk governance platform with an **Apple-inspired, minimal, and calm UI/UX**.

- **Module 1**: Understands APIs from OpenAPI/Swagger specifications, discovers auth schemes, inferred roles, resource models, and multi-step workflows, and generates prioritized OWASP API Security attack plans.
- **Module 2**: Converts attack plans into executable Bruno test collections on disk (`.bru` files), executes tests via Bruno CLI and high-speed async HTTP runner, manages multi-role identities, simulates stateful workflows, and executes adaptive follow-up probes.
- **Module 3**: Ingests execution results, verifies evidence to eliminate false positives, classifies vulnerabilities across 10 OWASP API categories, calculates transparent risk scores (0-100), generates attack graphs and compound attack chains, produces AI dual explanations and remediation pseudocode, automates fix verification, tracks regressions and scan history, and enforces machine-readable CI/CD security gates.
- **Frontend UI**: Apple/Linear/Raycast-inspired Next.js 14 + TypeScript + Tailwind CSS application featuring 12 views: Dashboard with animated ScoreRing, API Overview with interactive dependency map, OpenAPI drag-and-drop importer, Attack Center, Live Simulation, Vulnerability storytelling details, Attack Path diagram, AI Security Analyst, Fix Center (Before 200 vs After 403), History timeline, and Settings.

---

## Complete Core Pipeline

```
                         ┌────────────────────────────────┐
                         │   OpenAPI / Swagger 2.0 / 3.x  │
                         └───────────────┬────────────────┘
                                         │
                                         ▼
                         ┌────────────────────────────────┐
                         │      MODULE 1: Discovery &     │
                         │      Attack Plan Generation    │
                         └───────────────┬────────────────┘
                                         │ JSON Contract (/export/module2)
                                         ▼
                         ┌────────────────────────────────┐
                         │      MODULE 2: Bruno Runner &  │
                         │     Adaptive Attack Engine     │
                         └───────┬──────────────┬─────────┘
                                 │              │
                    ┌────────────┴───┐    ┌─────┴────────────┐
                    │ Bruno Files    │    │ Live API Target  │
                    │ (.bru / JSON)  │    │ (Local / Demo)   │
                    └────────────────┘    └─────┬────────────┘
                                                │ JSON Contract (/export/module3)
                                                ▼
                         ┌────────────────────────────────┐
                         │      MODULE 3: Intelligence,   │
                         │     Risk Engine, Fix Verify    │
                         │       & CI/CD Security Gate    │
                         └───────────────┬────────────────┘
                                         │
                                         ▼
                         ┌────────────────────────────────┐
                         │      FRONTEND UI (Apple-Style) │
                         │   Next.js, Tailwind, TypeScript│
                         └────────────────────────────────┘
```

---

## Quickstart & Launch Instructions

### 1. Start the Backend API (FastAPI)
```powershell
& ".\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive Swagger UI: `http://127.0.0.1:8000/docs`
- Embedded Vulnerable Demo Target: `http://127.0.0.1:8000/demo/docs`

### 2. Start the Frontend UI (Next.js)
```powershell
cd frontend
npm run dev
```
Open **`http://localhost:3000`** in your browser.

### 3. Run the Backend Automated Test Suite
```powershell
& ".\.venv\Scripts\python.exe" -m pytest -v --cov=app
```
*(All 52 test suites pass with 80% statement coverage across 4,137 statements)*

---

## Frontend UI Key Views

1. **Dashboard**: Greeting ("Good afternoon / TriageMate API"), large circular ScoreRing (94 Excellent), severity pills (0 Critical, 1 High, 3 Medium, 2 Low), Security Overview headline + action, Recent Activity timeline, and Quick Actions.
2. **API Overview**: API metadata, resource counts, interactive relationship map (`Users` $\rightarrow$ `Patients` $\rightarrow$ `Appointments` $\rightarrow$ `Triage` $\rightarrow$ `Reports`), and clickable endpoint catalog.
3. **API Import**: Drag-and-drop OpenAPI uploader, Bruno collection importer, raw JSON paste, and animated 5-step analysis sequence.
4. **Attack Center**: Categorized OWASP API test suites with issue counts and a safe confirmation modal.
5. **Live Simulation**: Real-time progress bar, live execution step feed, and critical finding discovery alert.
6. **Vulnerabilities**: Clean filterable list with risk score pills, HTTP method badges, and [View Finding] triggers.
7. **Vulnerability Detail Modal**: Storytelling format (What happened $\rightarrow$ Attack replay steps $\rightarrow$ Why this matters $\rightarrow$ How to fix with copy-pasteable pseudocode) + [Replay Attack] & [Verify Fix] buttons.
8. **Attack Path**: Interactive clean system diagram (`Role -> Endpoint -> Vulnerability -> Impact`) with clickable nodes and side inspection drawer.
9. **AI Security Analyst**: Integrated assistant panel with root-cause insights.
10. **Fix Center**: Interactive fix verification laboratory (Before 200 vs After 403) with animated steps and score bump.
11. **Security History**: Chronological scan timeline, score history trend graph, and regression comparisons.
12. **Settings**: Target configuration, AI provider selection (Deterministic, OpenAI GPT-4o, Ollama Local), and CI/CD Security Gate policy thresholds.
