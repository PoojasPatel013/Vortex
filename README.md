# Project Title: Vortex - Next-Generation Async Vulnerability Engine

## 1. Executive Summary

**Vortex** is a high-performance, modular vulnerability scanner built to address the limitations of legacy threaded scanners. Unlike traditional tools that rely on blocking I/O and heavy multiprocessing, Vortex utilizes a pure **AsyncIO event loop** architecture, allowing it to handle thousands of concurrent network connections with minimal resource overhead.

Vortex is not just a command-line tool; it is a full-scope security platform featuring a modern **React-based dashboard**, **Cloud-Native scanning capabilities**, and seamless **CI/CD integration**. It bridges the gap between offensive red-teaming tools and defensive blue-team monitoring dashboards.

## Quick Start & Usage

### Installation
```bash
# Clone repository
git clone https://github.com/PoojasPatel013/Vortex.git
cd Vortex

# Create virtual environment (Recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install .
```

### Running Scanners

**Basic Scan (Network & Web):**
```bash
python run.py scan example.com
```

**Advanced Scan (Network, Web, Cloud & IoT):**
```bash
python run.py scan example.com --cloud --iot
```

**Options:**
- `--cloud`: Enable Cloud Infrastructure Scanner (Public S3 Buckets)
- `--iot`: Enable IoT Protocol Fuzzer (MQTT Anonymous Login)
- `--auto-exploit`: Enable Pentest Engine (Auto-exploitation)
- `--ports`: Specify custom ports (e.g. `--ports 80,8080`)


## 2. Core Architecture & Tech Stack

The architecture is divided into three distinct layers: The Engine (Core), The Interface (API/UI), and The Integration Layer.

### A. The Engine (Vortex Core)

  * **Language:** Python 3.11+
  * **Concurrency Model:** `asyncio` (Event Loop) + `uvloop` (Ultra-fast event loop replacement)
  * **Network Library:** `aiohttp` (Async HTTP), `asyncio.Protocol` (Raw TCP/UDP)
  * **Why this stack?**
      * Demonstrates mastery of non-blocking I/O.
      * Reduces memory footprint compared to multi-threaded scanners (e.g., threading 1000 connections vs. awaiting 1000 coroutines).
      * Enables "massive scale" scanning (subnet/ASN level) on consumer hardware.

### B. The Interface (API & Dashboard)

  * **Backend API:** FastAPI (Asynchronous Python web framework)
  * **Frontend:** React.js + Tailwind CSS + Recharts (for data visualization)
  * **Communication:** REST API & WebSockets (for real-time scan progress updates)
  * **Database:** PostgreSQL (for persistent scan history) or Redis (for high-speed job queues).
  * **Why this stack?**
      * Decouples the scanning engine from the user interface.
      * Allows for "Headless" operation (API mode) or "Interactive" operation (GUI mode).

### C. The Integration Layer (DevOps)

  * **Containerization:** Docker & Docker Compose
  * **CI/CD:** GitHub Actions (Custom Action wrapper)
  * **Notification:** Webhooks (Slack/Discord integration)

-----

## 3. Key Features & Modules

Vortex extends the capabilities of traditional scanners by incorporating modern infrastructure targets.

### 🌐 Module A: Async Network & Web Scanner

  * **Port Scanning:** Non-blocking TCP connect scanner.
  * **HTTP Analysis:** Async header analysis, SSL certificate validation, and tech stack fingerprinting.
  * **Innovation:** Uses a "producer-consumer" pattern where one coroutine finds open ports and instantly queues them for the service identification coroutine, minimizing idle time.

### ☁️ Module B: Cloud Infrastructure Scanner

  * **AWS Misconfiguration:** Uses `aiobotocore` (Async AWS SDK) to check for:
      * Public S3 Buckets.
      * Security Groups allowing `0.0.0.0/0` on sensitive ports (SSH/RDP).
  * **Kubernetes Auditing:** Checks for exposed API Servers and unauthenticated Kubelet endpoints.
  * **Why this matters:** Shifts focus from "Server Vulnerabilities" to "Infrastructure Configuration," a key requirement for modern DevSecOps.

### 📡 Module C: IoT Protocol Fuzzer

  * **MQTT & CoAP Support:** Specialized modules to connect to IoT message brokers.
  * **Checks:** Anonymous login detection, wildcard subscription data leakage.
  * **Implementation:** Custom-written async protocol handlers for lightweight IoT interaction.

-----

## 4. The "Vortex UI" Dashboard

A standalone web interface designed for Blue Teams and Management to visualize security posture.

  * **Live Attack Surface Map:** A force-directed graph (D3.js) showing the relationship between domains, subdomains, and open ports.
  * **Real-Time Progress:** WebSocket connection streams scan logs directly to the browser console window.
  * **Diff-View:** A "Time Machine" feature that compares Scan A (Last Week) vs. Scan B (Today) to highlight *newly opened* ports or *new* misconfigurations.

-----

## 5. Deployment & Automation Strategy

To prove the "Shift Left" capability, Vortex includes a native CI/CD wrapper.

### GitHub Action Integration

  * **Repository:** `vortex-action`
  * **Usage:**
    ```yaml
    - name: Run Vortex Security Scan
      uses: your-repo/vortex-action@v1
      with:
        target: ${{ secrets.STAGING_URL }}
        fail-on-severity: high
    ```
  * **Behavior:** The action pulls the Docker container, runs a scan against the staging environment, parses the JSON output, and fails the build pipeline if critical vulnerabilities are found.

### ChatOps (Slack/Discord)

  * **Bot Integration:** A listener bot that accepts commands like `/vortex scan target.com`.
  * **Reporting:** Upon completion, the bot posts a PDF summary to the channel and links to the full dashboard report.

-----

## 6. Roadmap & Future Innovations

  * **AI False Positive Reduction:** Implementation of an OpenAI API post-processor to analyze raw HTTP responses and assign a "Confidence Score" to vulnerabilities.
  * **Distributed Scanning:** Using Redis Pub/Sub to coordinate multiple Vortex nodes scanning different IP ranges simultaneously.
