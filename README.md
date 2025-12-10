# NETRA - Enterprise Attack Surface Management (ASM)

## 1. Product Vision
NETRA is not just a scanner; it is a **Continuous Attack Surface Management (ASM)** platform designed for modern, cloud-native enterprises.

While traditional scanners wait for you to define a target, NETRA continuously monitors your infrastructure to detect **Shadow IT**, **Zombie APIs**, and **Compliance Drifts** in real-time. Built on a scalable Kubernetes-native architecture, it scales from a single startup website to Fortune 500 infrastructure effortlessly.

---

## 2. The "NETRA Advantage" (Key Differentiators)

### 🛡️ Feature A: Automated Asset Discovery (Reconnaissance)
**The Problem**: Companies don't know what they own.
**The Solution**: Input a company name, and NETRA performs deep recursive enumeration:
*   **Certificate Transparency Logs**: Finds subdomains before they are even live.
*   **Cloud Hunter**: Scans AWS, Azure, and GCP IP ranges for assets belonging to the organization.
*   **Acquisition Mapping**: Links subsidiary companies to the main dashboard.

### ⚖️ Feature B: GRC & Compliance Engine
**The Problem**: Security teams speak "vulnerabilities"; C-Levels speak "risk."
**The Solution**: Every finding is automatically mapped to major compliance frameworks.
*   **Open S3 Bucket** → Mapped to **HIPAA §164.312(a)(1)**
*   **Weak SSL Cipher** → Mapped to **PCI-DSS Req 4.1**
**Benefit**: Generates audit-ready PDF reports instantly.

### 🧟 Feature C: "Zombie" API Detection
**The Problem**: Undocumented APIs are the easiest way to breach a company.
**The Solution**: NETRA parses client-side JavaScript bundles to extract API routes that are not in the official documentation (Shadow APIs) and tests them for **Broken Object Level Authorization (BOLA)**.

---

## 3. Enterprise Architecture
NETRA is designed to handle massive scale using a distributed microservices architecture.

### The Stack
*   **Orchestration**: Kubernetes (Helm Charts provided).
*   **Queue System**: Redis Streams (Distributes millions of targets to workers).
*   **Data Lake**: PostgreSQL (Persistent History) & AsyncIO Engine.
*   **Identity**: Keycloak (OIDC/SAML integration for Enterprise SSO).

### Deployment (Helm)
```bash
helm repo add netra https://charts.netra-security.io
helm install netra-platform netra/enterprise --set replicas=50
```

### Local Development (Docker Compose)
For testing and development, you can spin up the distributed cluster locally:
```bash
# Clone repository
git clone https://github.com/PoojasPatel013/Netra.git
cd Vortex

# Start Commander, Database, Redis, and Worker Drone
docker-compose up --build
```

---

## 4. Integration Ecosystem
NETRA fits into the modern DevSecOps pipeline:
*   **Ticket Systems**: 2-way sync with Jira and ServiceNow. (A bug found in NETRA automatically creates a Jira ticket; closing the Jira ticket triggers a re-scan in NETRA).
*   **SIEM**: Forwards logs to Splunk or Datadog via webhooks.
*   **CI/CD**: Blocks Jenkins/GitLab builds if critical API vulnerabilities are found.

---

## 5. Roadmap: The Path to Series A
*   **Q1: AI-Powered Remediation**: Using LLMs to not just find the bug, but generate the specific code patch to fix it (e.g., "Here is the Nginx config to fix your missing security headers").
*   **Q2: Agentless Cloud Security**: Direct integration with AWS IAM roles to scan internal VPCs without deploying scanners.
*   **Q3: SaaS Multi-Tenancy**: Re-architecting for a SaaS model where multiple companies share the same infrastructure with strict data isolation.
