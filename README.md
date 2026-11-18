# 🛡️ SentinelAI — AI-Enhanced Security Information and Event Management (SIEM) System for Intelligent Threat Detection and Log Analysis

> An AI-powered Security Information and Event Management (SIEM) platform that transforms raw security logs into actionable threat intelligence through intelligent log analysis, rule-based threat detection, and AI-assisted incident investigation.

<p align="center">
  <strong>Turning Security Logs into Actionable Intelligence</strong>
</p>

---

## 📌 Overview

**SentinelAI** is a web-based Security Information and Event Management (SIEM) system designed to simplify security monitoring and threat investigation.

Traditional security monitoring often requires analysts to manually inspect large volumes of system logs to identify suspicious activities. SentinelAI addresses this challenge by automating log parsing, detecting potentially malicious patterns, and using AI to analyze suspicious events.

The application allows users to upload security log files, identify suspicious activities, investigate potential threats, and visualize security incidents through an interactive dashboard.

SentinelAI demonstrates how rule-based detection and Large Language Models (LLMs) can work together to support cybersecurity operations.

## ✨ Features

### 1. Security Log Upload

- Upload `.log` and `.txt` security log files.
- Supports SSH authentication logs and simple key-value application logs.
- Processes uploaded files and extracts individual log entries.
- Maintains uploaded file information and processing status.

### 2. Intelligent Log Parsing

Converts unstructured log entries into structured records containing:

- Timestamp
- IP address
- Username
- Event type
- Hostname
- Message
- Original raw log entry

Structured records make security events easier to search, analyze, and investigate.

### 3. Rule-Based Threat Detection

The detection engine examines structured logs and identifies suspicious activity using configurable detection rules.

Supported detection scenarios include:

- Brute-force login attempts
- Repeated authentication failures
- Unauthorized access attempts
- Suspicious IP activity
- Credential-stuffing patterns
- Generic authentication failures

Detection thresholds can be configured to control how suspicious activity is identified.

### 4. AI-Powered Incident Analysis

SentinelAI uses an AI analysis engine to investigate suspicious events and generate meaningful security insights.

The AI engine provides:

- Attack type identification
- Threat severity classification
- Explanation of suspicious activity
- Plain-language incident summaries
- Recommended mitigation steps

**Supported AI providers:**

- OpenAI API
- Ollama (Llama 3 / Mistral)
- Simulated AI provider for offline demonstrations

The simulated provider allows the application to demonstrate its complete workflow without requiring an external API key.

### 5. Interactive Security Dashboard

The dashboard provides an overview of security incidents and their characteristics.

Dashboard visualizations include:

- Total incident counts
- Alert counts by severity
- Severity distribution
- Attack-type distribution
- 14-day incident trend
- Recent security incidents
- AI-generated threat summaries
- Attack timelines

### 6. Incident Management

Users can investigate and manage detected incidents through the incident management interface.

- View incident history.
- Search incidents.
- Filter by severity.
- Filter by attack type.
- Sort incident records.
- View detailed incident information.
- Delete incident records.

### 7. Security Report Generation

Export incident history for documentation and further analysis.

Supported export formats:

- PDF
- CSV

These reports can be used for security documentation, project demonstrations, and incident review.

---

## 🧰 Built With

SentinelAI uses a combination of Python-based backend technologies, frontend technologies, database management, and AI integration.

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| Flask | Backend web framework |
| HTML5 | Application structure |
| CSS3 | Styling and layout |
| JavaScript | Frontend interactions |
| Bootstrap 5 | Responsive UI components |
| Chart.js | Dashboard visualizations |
| SQLite | Persistent data storage |
| OpenAI API | LLM-powered incident analysis |
| Ollama | Local LLM integration |
| Llama 3 / Mistral | Local language models |
| ReportLab | PDF report generation |

---

## 🏗️ System Architecture

SentinelAI follows a modular architecture in which uploaded security logs pass through multiple processing and analysis stages.

```text
             SECURITY LOG FILES
              (.log / .txt)
                    |
                    v
             LOG UPLOAD MODULE
                    |
                    v
              LOG PARSER
                    |
                    v
            STRUCTURED LOG DATA
                    |
                    v
             RULE-BASED ENGINE
                    |
                    v
          SUSPICIOUS EVENT FILTER
                    |
                    v
              AI ENGINE
          /        |         \
         /         |          \
     OpenAI      Ollama    Simulated AI
         \         |          /
          \        |         /
           v       v        v
          INCIDENT ANALYSIS
                    |
                    v
             SQLITE DATABASE
                    |
             +------+------+
             |             |
             v             v
       SOC DASHBOARD   REPORT EXPORT
       (Chart.js)      (PDF / CSV)
```

### Processing Workflow

1. **Log ingestion:** Users upload security log files through the web interface.
2. **Log parsing:** Raw log entries are converted into structured records.
3. **Threat detection:** The rule engine evaluates structured records against predefined detection rules.
4. **AI analysis:** Suspicious findings are forwarded to the configured AI provider.
5. **Incident storage:** Processed incidents and their analysis results are stored in SQLite.
6. **Visualization:** The dashboard displays incident statistics, threat distributions, and investigation details.
7. **Reporting:** Users can export incident history into PDF or CSV files.

---

## 🚀 Getting Started

Follow these instructions to set up and run SentinelAI locally.

### Prerequisites

Make sure you have the following installed:

- Python 3.8 or higher
- pip (Python package manager)
- Git

For real AI-powered analysis, you will also need either:

- An OpenAI API key, or
- Ollama with a supported local language model.

**Note:** You can run the application using its default simulated AI provider without configuring either service.

### 1. Clone the Repository

```bash
git clone https://github.com/kavinanandr/ai-enhanced-siem-system.git
```

### 2. Navigate to the Project Directory

```bash
cd ai-enhanced-siem-system
```

### 3. Create a Virtual Environment

```bash
python3 -m venv venv
```

### 4. Activate the Virtual Environment

**Linux / macOS:**

```bash
source venv/bin/activate
```

**Windows (PowerShell):**

```powershell
venv\Scripts\Activate.ps1
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the Application

```bash
python app.py
```

### 7. Open the Application

Navigate to the following address in your browser:

```text
http://127.0.0.1:5000
```

The application should now be running locally.

### 8. Try the Sample Logs

Navigate to the **Upload Logs** section and upload the sample files available in the `sample_logs/` directory.

Available sample files:

- `sample_auth.log`
- `sample_app_events.txt`

These files allow you to test the complete processing workflow:

```text
Upload → Parse → Detect → Analyze → Dashboard
```

---

## 🤖 Configuring AI Providers

SentinelAI supports multiple AI analysis providers. You can select a provider using environment variables without modifying the application source code.

### 1. Simulated AI (Default)

The default provider is `simulated`.

It requires:
- No API key
- No external AI service
- No internet connection

It generates deterministic incident summaries based on detected security findings.

This mode is useful for demonstrations, development, and offline testing.

### 2. OpenAI Integration

To enable OpenAI-powered incident analysis, configure the following environment variables.

**Linux / macOS:**

```bash
export SIEM_AI_PROVIDER=openai
export OPENAI_API_KEY=your_api_key
export OPENAI_MODEL=gpt-4o-mini
```

**Windows (PowerShell):**

```powershell
$env:SIEM_AI_PROVIDER="openai"
$env:OPENAI_API_KEY="your_api_key"
$env:OPENAI_MODEL="gpt-4o-mini"
```

Start the application:

```bash
python app.py
```

### 3. Ollama Integration

Ollama enables local LLM inference without depending on an external AI API.

First, install Ollama and download a supported model.

```bash
ollama pull llama3
```

Start the Ollama service:

```bash
ollama serve
```

Configure the application.

**Linux / macOS:**

```bash
export SIEM_AI_PROVIDER=ollama
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=llama3
```

**Windows (PowerShell):**

```powershell
$env:SIEM_AI_PROVIDER="ollama"
$env:OLLAMA_HOST="http://localhost:11434"
$env:OLLAMA_MODEL="llama3"
```

Run the application:

```bash
python app.py
```

**Fallback mechanism:** If the configured AI provider encounters an error, SentinelAI automatically falls back to the simulated analyst for that incident. The actual provider used is recorded with the incident.

---

## 📂 Project Structure

The project follows a modular directory structure to separate AI analysis, log processing, detection, database operations, reporting, and frontend resources.

```text
ai-enhanced-siem-system/
│
├── ai/
│   └── ai_engine.py
│       # AI-powered incident analysis
│       # OpenAI, Ollama, and simulated providers
│
├── data/
│   └── siem.db
│       # SQLite database (generated automatically)
│
├── database/
│   ├── db.py
│   │   # Database connection and schema initialization
│   │
│   └── models.py
│       # Database access and data operations
│
├── detection/
│   ├── log_parser.py
│   │   # Converts raw logs into structured records
│   │
│   └── rule_engine.py
│       # Identifies suspicious activities
│
├── logs/
│   # Stores uploaded raw log files
│
├── reports/
│   └── report_generator.py
│       # PDF and CSV report generation
│
├── sample_logs/
│   ├── sample_auth.log
│   └── sample_app_events.txt
│       # Sample security logs for testing
│
├── static/
│   ├── css/
│   │   └── style.css
│   │       # Application styles
│   │
│   └── js/
│       ├── dashboard.js
│       ├── upload.js
│       └── incidents.js
│           # Frontend functionality
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── upload.html
│   ├── view_logs.html
│   ├── dashboard.html
│   ├── incidents.html
│   └── reports.html
│       # Flask HTML templates
│
├── app.py
│   # Main Flask application and routes
│
├── config.py
│   # Application configuration and detection thresholds
│
├── requirements.txt
│   # Python dependencies
│
├── .gitignore
│
└── README.md
```

*Note: The SQLite database and uploaded log files are created or populated during application usage.*

---

## 🗄️ Database Design

SentinelAI uses SQLite for persistent storage.

The application maintains three primary data entities.

### 1. Files

Stores information about uploaded log files.

| Field | Description |
|---|---|
| id | Unique file identifier |
| filename | Original filename |
| stored_path | Location of the uploaded file |
| upload_time | Upload timestamp |
| log_count | Number of processed log entries |
| status | Processing status |

### 2. Logs

Stores parsed and structured security log entries.

| Field | Description |
|---|---|
| id | Unique log identifier |
| file_id | Associated uploaded file |
| timestamp | Event timestamp |
| ip_address | Source IP address |
| username | Associated username |
| event_type | Type of security event |
| host_name | Host associated with the event |
| message | Parsed log message |
| raw_line | Original log entry |
| is_suspicious | Suspicious activity indicator |
| created_at | Record creation timestamp |

### 3. Incidents

Stores detected security incidents and AI-generated analysis.

| Field | Description |
|---|---|
| id | Unique incident identifier |
| file_id | Associated uploaded file |
| log_id | Associated log entry |
| attack_type | Identified attack category |
| severity | Incident severity |
| reason | Detection explanation |
| ai_summary | AI-generated incident summary |
| recommendation | Suggested mitigation |
| source_ip | Source IP address |
| username | Associated username |
| ai_provider | Provider used for analysis |
| created_at | Incident creation timestamp |

---

## ⚙️ Detection Configuration

Detection thresholds can be customized in `config.py`.

Default detection thresholds include:

| Detection Rule | Threshold |
|---|---|
| Brute-force detection | At least 5 failed logins from one IP within 10 minutes |
| Suspicious IP activity | At least 4 distinct usernames from one IP within 15 minutes |

These thresholds determine when authentication patterns are considered suspicious.

Adjusting them allows the detection engine to be configured for different testing scenarios.

---

## 📊 Application Modules

| Module | Responsibility |
|---|---|
| `app.py` | Application entry point and Flask routes |
| `config.py` | Centralized configuration |
| `ai/` | AI-powered incident analysis |
| `detection/` | Log parsing and threat detection |
| `database/` | SQLite database operations |
| `reports/` | PDF and CSV report generation |
| `static/` | CSS and JavaScript assets |
| `templates/` | Frontend HTML templates |
| `sample_logs/` | Sample security log datasets |

---

## 🔐 Security Considerations

SentinelAI is an educational cybersecurity project intended for development, testing, and demonstration purposes.

When running the application:

- Never commit API keys or other credentials to GitHub.
- Keep API keys in environment variables.
- Use trusted log files when testing.
- Avoid uploading sensitive production logs to external AI providers without appropriate authorization.
- Treat AI-generated security recommendations as analyst assistance rather than guaranteed security decisions.

---

## 🎯 Project Scope and Limitations

SentinelAI demonstrates a simplified SIEM workflow and is not intended to replace an enterprise-grade SIEM platform.

The current implementation focuses on:

- Manual log-file ingestion
- Structured log parsing
- Rule-based threat detection
- AI-assisted incident analysis
- Dashboard visualization
- Incident history management
- PDF and CSV reporting

The following capabilities are outside the current implementation:

- Enterprise-scale distributed log ingestion
- Continuous real-time system log collection
- Automatic firewall-based threat blocking
- Multi-user authentication and authorization
- Commercial SIEM integrations
- ML-based anomaly detection
- Threat intelligence feed integration

These areas can be considered for future development.

---

## 🚀 Future Enhancements

Potential improvements include:

- Real-time log monitoring and streaming.
- Machine-learning-based anomaly detection.
- MITRE ATT&CK framework integration.
- Threat intelligence enrichment.
- Automated email notifications.
- Advanced incident correlation.
- Role-based access control.
- Cloud deployment.
- Automated incident response workflows.

---

## 👨‍💻 Author

**Kavin Anand**


- GitHub: [@kavinanandr](https://github.com/kavinanandr)
- Project Repository: [AI-Enhanced SIEM System](https://github.com/kavinanandr/ai-enhanced-siem-system)

---

## 📄 License

This project is intended for educational and demonstration purposes.

Please check the repository for licensing information before redistributing or reusing the source code.

---

<p align="center">
  <strong>SentinelAI — Making Security Monitoring Smarter.</strong>
  <br/>
  Built with Python, Flask, and AI.
</p>