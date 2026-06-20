# AmanScan

**AmanScan** is a Python desktop application built with **PyQt5** for defensive **Security Exposure Intelligence**.  
It helps security teams, system administrators, and cybersecurity students collect and correlate public exposure data about domains, URLs, and IP addresses using OSINT and vulnerability-intelligence sources.

> **Defensive and educational use only.** Use AmanScan only on systems you own or are explicitly authorized to assess.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [How AmanScan Works](#how-amanscan-works)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Configuration and API Keys](#configuration-and-api-keys)
- [Usage](#usage)
- [Risk Scoring Model](#risk-scoring-model)
- [Reports and Exporting](#reports-and-exporting)
- [Local Scan History](#local-scan-history)
- [Security and Ethical Notice](#security-and-ethical-notice)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Suggested Roadmap](#suggested-roadmap)
- [License](#license)
- [Arabic Documentation](#التوثيق-العربي)

---

## Overview

AmanScan performs a defensive, passive security-exposure assessment for one or more targets.

Supported target examples:

```text
example.com
https://example.com
8.8.8.8
```

After receiving the target list, AmanScan normalizes each target, resolves the host to an IP address when possible, collects exposure and vulnerability information from multiple sources, correlates the findings, calculates a risk score, and generates a readable security report.

The application is designed as a **desktop GUI tool**, not a command-line-only scanner.  
Its main entry point is:

```text
amanscan.py
```

---

## Key Features

### 1. Passive Exposure Intelligence

AmanScan collects externally available exposure information without acting as an aggressive exploitation tool.

It can help identify:

- Publicly exposed services.
- Open ports reported by external intelligence sources.
- Related CVEs.
- Known exploited vulnerabilities.
- Public exploit indicators.
- General risk level for each target.

### 2. Multi-Target Portfolio Scan

The application supports scanning multiple assets in one run.  
Each target is entered on a separate line, then processed through the same analysis pipeline.

### 3. OSINT and Vulnerability Intelligence Sources

AmanScan is structured to integrate with several sources, including:

- **Web-Check**
- **Shodan**
- **Shodan InternetDB**
- **ZoomEye**
- **NVD**
- **FIRST EPSS**
- **CISA KEV**
- **Searchsploit**
- **GitHub PoC indicators**
- **OpenAI analysis**

Some integrations require API keys or external tools to be installed.

### 4. Risk Scoring

AmanScan calculates risk using a model that combines:

- CVSS impact.
- EPSS exploitation probability.
- Exposure level.
- Public exploit evidence.
- CISA KEV presence.

Each CVE is categorized into:

- Critical
- High
- Medium
- Low
- Info

### 5. PyQt5 Graphical Interface

The GUI includes multiple sections:

- Dashboard
- Scan
- Findings
- Report
- Trend
- Settings

The interface also includes an optional HUD-style scan grid overlay.

### 6. Report Generation

AmanScan can generate reports containing:

- Target summary.
- IP and host information.
- Services and exposure profile.
- CVE list.
- CVSS data.
- EPSS data.
- CISA KEV indicators.
- Public exploit indicators.
- AI-generated analysis when enabled.
- Defensive remediation guidance.

### 7. Local Scan History

Scan summaries are stored locally using SQLite.  
This allows the Trend page to show previous results for a selected target.

---

## How AmanScan Works

The general workflow is:

1. The user enters one or more targets in the Scan page.
2. The application loads local configuration.
3. Each target is normalized.
4. The host is extracted from the URL or input.
5. AmanScan attempts to resolve the host to an IP address.
6. Enabled intelligence sources are queried.
7. Services and CVEs are collected and deduplicated.
8. NVD data is used to enrich CVEs when enabled.
9. Exploit intelligence is added using EPSS, KEV, Searchsploit, GitHub, and Shodan data.
10. Risk score and severity are calculated.
11. Optional AI analysis is generated.
12. A report is built.
13. The scan summary is saved locally.

---

## Project Structure

```text
AmanScan/
├── ai/
│   └── analyzer.py
│
├── config/
│   └── config_manager.py
│
├── core/
│   ├── correlator.py
│   ├── epss_client.py
│   ├── exploit_intel.py
│   ├── nvd_client.py
│   ├── risk.py
│   ├── shodan_client.py
│   ├── telemetry.py
│   ├── webcheck_client.py
│   └── zoomeye_client.py
│
├── report/
│   └── report_builder.py
│
├── ui/
│   ├── about_dialog.py
│   ├── icons.py
│   ├── main_window.py
│   ├── overlays.py
│   ├── settings_window.py
│   └── styles.py
│
├── amanscan.py
├── README.md
├── README_AmanScan.md
└── requirements.txt
```

### Important Files

| File | Description |
|---|---|
| `amanscan.py` | Main application entry point. |
| `ui/main_window.py` | Main GUI window, navigation pages, scan execution, report preview, and export actions. |
| `ui/settings_window.py` | Settings page for API keys and feature toggles. |
| `ui/overlays.py` | HUD grid overlay used in the interface. |
| `config/config_manager.py` | Loads and saves local application configuration. |
| `core/correlator.py` | Main scan orchestration and correlation engine. |
| `core/risk.py` | Risk scoring, severity mapping, service profiling, and remediation playbooks. |
| `core/shodan_client.py` | Shodan and InternetDB integration. |
| `core/zoomeye_client.py` | ZoomEye integration. |
| `core/nvd_client.py` | NVD CVE and CPE enrichment. |
| `core/epss_client.py` | EPSS lookup logic. |
| `core/exploit_intel.py` | Exploit-intelligence correlation using KEV, EPSS, Searchsploit, GitHub, and other signals. |
| `core/telemetry.py` | Local scan-history storage. |
| `ai/analyzer.py` | Optional AI-based analysis. |
| `report/report_builder.py` | HTML report generation. |
| `requirements.txt` | Python dependencies. |

---

## Requirements

Recommended environment:

- Python 3.10 or newer
- pip
- Virtual environment
- Windows, Linux, or macOS with PyQt5 support

Python dependencies:

```text
PyQt5>=5.15.9
requests>=2.31.0
reportlab>=4.0.0
zoomeye>=3.0.0
openai>=1.0.0
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/abedalrahman-manasrah/AmanScan.git
cd AmanScan
```

### 2. Create a Virtual Environment

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Application

```bash
python amanscan.py
```

If your system uses `python3` instead of `python`, run:

```bash
python3 amanscan.py
```

---

## Configuration and API Keys

AmanScan stores local configuration in:

```text
~/.config/amanscan/config.json
```

The local scan-history database is stored in:

```text
~/.config/amanscan/history.sqlite
```

You can configure API keys from the **Settings** page inside the application.

Example configuration:

```json
{
  "shodan_api_key": "YOUR_SHODAN_KEY",
  "zoomeye_api_key": "YOUR_ZOOMEYE_KEY",
  "openai_api_key": "YOUR_OPENAI_KEY",
  "openai_model": "gpt-5",
  "github_token": "YOUR_GITHUB_TOKEN",
  "webcheck_base_url": "http://127.0.0.1:8080",
  "nvd_api_key": "YOUR_NVD_KEY",

  "enable_webcheck": true,
  "enable_shodan": true,
  "enable_zoomeye": true,
  "enable_nvd": true,
  "enable_ai": true,

  "ui_theme": "hud_dark"
}
```

### Optional Integrations

| Integration | Requirement |
|---|---|
| Shodan | Shodan API key |
| ZoomEye | ZoomEye API key |
| NVD | NVD API key, optional but recommended |
| OpenAI | OpenAI API key |
| GitHub PoC Search | GitHub token, optional |
| Web-Check | Local or remote Web-Check API base URL |
| Searchsploit | Searchsploit installed and available in PATH |

> Never commit real API keys or local configuration files to GitHub.

---

## Usage

1. Start the application:

```bash
python amanscan.py
```

2. Open **Settings** and configure the required API keys.

3. Go to **Scan**.

4. Enter targets, one per line:

```text
example.com
https://example.org
8.8.8.8
```

5. Click **Start Portfolio Scan**.

6. Monitor the progress bar and logs.

7. After the scan finishes, review:

- **Dashboard** for the overall summary.
- **Findings** for technical findings.
- **Report** for the generated report.
- **Trend** for historical scan results.
- **Settings** to adjust integrations.

8. Export the results as needed:

- HTML
- PDF
- JSON

---

## Risk Scoring Model

AmanScan uses a risk score from `0` to `100`.

The base formula is:

```text
Risk Score = CVSS × EPSS × Exposure
```

Then the score is adjusted with additional exploit signals:

```text
+8  if public exploit evidence exists
+20 if the CVE exists in CISA KEV
```

The final value is clamped between `0` and `100`.

### Severity Mapping

| Score Range | Severity |
|---:|---|
| 85 - 100 | Critical |
| 65 - 84 | High |
| 40 - 64 | Medium |
| 15 - 39 | Low |
| 0 - 14 | Info |

### Exposure Hint

AmanScan estimates exposure using detected services and ports.  
Some sensitive ports increase the exposure score more than normal web ports.

Examples of sensitive services:

| Service | Port |
|---|---:|
| SSH | 22 |
| Telnet | 23 |
| RDP | 3389 |
| MySQL | 3306 |
| PostgreSQL | 5432 |
| Redis | 6379 |
| Elasticsearch | 9200 |
| MongoDB | 27017 |

---

## Reports and Exporting

AmanScan supports exporting results in multiple formats.

### HTML

A readable browser-based report.

### PDF

A PDF copy of the current report.

### JSON

A machine-readable export of portfolio scan results.

Example JSON structure:

```json
[
  {
    "target_url": "https://example.com",
    "host": "example.com",
    "ip": "93.184.216.34",
    "services": [],
    "zoomeye_hits": [],
    "cves": [],
    "profiles": {},
    "risk_summary": {
      "exposure_hint_0_15": 0,
      "overall_risk_0_100": 0,
      "counts": {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
      }
    }
  }
]
```

---

## Local Scan History

AmanScan stores scan summaries locally using SQLite.

The local history can include:

- Scan time.
- Target.
- Host.
- IP address.
- Exposure score.
- Overall risk score.
- Top CVSS score.
- KEV count.
- Severity counts.

This information is used by the **Trend** page.

---

## Security and Ethical Notice

AmanScan is intended for:

- Defensive asset review.
- Internal security assessment.
- Educational cybersecurity projects.
- OSINT and vulnerability-intelligence learning.
- Authorized security reporting.

Do not use AmanScan for:

- Unauthorized scanning.
- Targeting systems you do not own.
- Collecting intelligence against third parties without permission.
- Any offensive or illegal activity.
- Violating API provider terms.

---

## Limitations

AmanScan is not a full penetration-testing framework and does not replace professional vulnerability management.

Possible limitations include:

- External intelligence may be outdated.
- Results may contain false positives.
- Some sources require paid or rate-limited API keys.
- CVE mapping depends on available CPE/service data.
- AI analysis is only as accurate as the collected scan data.
- Passive exposure data may not reflect the real internal security posture.

---

## Troubleshooting

### The application does not start

Reinstall dependencies:

```bash
pip install -r requirements.txt
```

Then run:

```bash
python amanscan.py
```

### PyQt5 installation error

Try upgrading pip and reinstalling PyQt5:

```bash
python -m pip install --upgrade pip
pip install --force-reinstall PyQt5
```

### Shodan results are missing

Check that:

- The Shodan API key is configured.
- Shodan integration is enabled.
- The API key has enough quota.
- The target resolves correctly.

### ZoomEye results are missing

Check that:

- The ZoomEye API key is configured.
- ZoomEye integration is enabled.
- The API key is valid.
- The target IP is valid.

### AI analysis does not work

Check that:

- OpenAI API key is configured.
- AI analysis is enabled.
- The selected model is valid.
- Internet access is available.

### Web-Check connection fails

Make sure the Web-Check service is running and that `webcheck_base_url` points to the correct URL.

### Searchsploit returns no results

Verify that Searchsploit is installed:

```bash
searchsploit --help
```

---

## Suggested Roadmap

Possible future improvements:

- Add screenshots to the README.
- Add an English-only quick-start guide.
- Add Docker support.
- Add CLI mode.
- Add CSV export.
- Add unit tests for core modules.
- Add GitHub Actions for linting and tests.
- Add packaged executable builds for Windows, Linux, and macOS.
- Add a plugin system for additional OSINT sources.
- Add comparison between two scans of the same target.
- Add alerts when risk increases compared with previous scans.
- Add `config.example.json`.

---

## License

No clear license file is currently included.

Before publishing or distributing the project, consider adding a `LICENSE` file.

Common choices:

- MIT License
- Apache License 2.0
- GPL License

---

## Author

Repository owner:

```text
ENG: Abed Alrahman Manasrah
Abdulhamid Zaro
```

Project name:

```text
AmanScan
```

---

# التوثيق العربي

## AmanScan

**AmanScan** هو تطبيق سطح مكتب مبني بلغة **Python** وواجهة **PyQt5** لتحليل مستوى التعرّض الأمني للأهداف بشكل دفاعي اعتمادًا على مصادر OSINT وخدمات استخبارات الثغرات.

يساعد التطبيق فرق الأمن، مسؤولي الأنظمة، وطلاب الأمن السيبراني على جمع وربط معلومات عامة حول الدومينات، الروابط، وعناوين IP، ثم تحويل هذه المعلومات إلى تقرير أمني واضح.

> **الاستخدام دفاعي وتعليمي فقط.** استخدم AmanScan فقط على الأنظمة التي تملكها أو لديك تصريح رسمي لتقييمها.

---

## المحتويات العربية

- [نظرة عامة](#نظرة-عامة)
- [الميزات الرئيسية](#الميزات-الرئيسية-1)
- [آلية عمل AmanScan](#آلية-عمل-amanscan)
- [هيكل المشروع](#هيكل-المشروع-1)
- [المتطلبات](#المتطلبات-1)
- [التثبيت](#التثبيت)
- [تشغيل التطبيق](#تشغيل-التطبيق)
- [الإعدادات ومفاتيح API](#الإعدادات-ومفاتيح-api)
- [طريقة الاستخدام](#طريقة-الاستخدام)
- [نموذج تقييم المخاطر](#نموذج-تقييم-المخاطر)
- [التقارير والتصدير](#التقارير-والتصدير)
- [سجل الفحوصات المحلي](#سجل-الفحوصات-المحلي)
- [ملاحظات أمنية وأخلاقية](#ملاحظات-أمنية-وأخلاقية)
- [حدود المشروع](#حدود-المشروع)
- [استكشاف الأخطاء](#استكشاف-الأخطاء)
- [خارطة تطوير مقترحة](#خارطة-تطوير-مقترحة)
- [الرخصة](#الرخصة)
- [المؤلف](#المؤلف)

---

## نظرة عامة

يقوم AmanScan بتنفيذ فحص دفاعي سلبي لمستوى التعرّض الأمني لهدف واحد أو عدة أهداف.

أمثلة على الأهداف المدعومة:

```text
example.com
https://example.com
8.8.8.8
```

بعد إدخال الأهداف، يقوم التطبيق بتطبيع الهدف، استخراج اسم المضيف، محاولة حلّه إلى عنوان IP، جمع البيانات من مصادر استخبارات أمنية مختلفة، ربط النتائج، حساب درجة خطورة، ثم توليد تقرير قابل للقراءة.

التطبيق مصمم كأداة بواجهة رسومية Desktop GUI وليس كأداة أوامر فقط.  
نقطة التشغيل الرئيسية هي:

```text
amanscan.py
```

---

## الميزات الرئيسية

### 1. استخبارات تعرّض دفاعية Passive

يجمع AmanScan معلومات التعرّض المتاحة من مصادر عامة دون أن يكون أداة استغلال هجومية.

يساعد في تحديد:

- الخدمات المكشوفة للعامة.
- المنافذ المفتوحة حسب مصادر خارجية.
- الثغرات المرتبطة CVEs.
- الثغرات المعروفة والمستغلة.
- مؤشرات وجود استغلال عام.
- مستوى الخطورة العام لكل هدف.

### 2. فحص عدة أهداف

يدعم التطبيق إدخال أكثر من هدف في نفس الفحص.  
كل هدف يتم وضعه في سطر مستقل، ثم تتم معالجته داخل نفس Pipeline.

### 3. مصادر OSINT واستخبارات الثغرات

تم بناء AmanScan للتكامل مع عدة مصادر، مثل:

- **Web-Check**
- **Shodan**
- **Shodan InternetDB**
- **ZoomEye**
- **NVD**
- **FIRST EPSS**
- **CISA KEV**
- **Searchsploit**
- **GitHub PoC indicators**
- **OpenAI analysis**

بعض هذه المصادر يحتاج مفاتيح API أو أدوات خارجية مثبتة على الجهاز.

### 4. تقييم المخاطر Risk Scoring

يحسب AmanScan درجة الخطورة اعتمادًا على:

- تأثير الثغرة حسب CVSS.
- احتمالية الاستغلال حسب EPSS.
- مستوى التعرّض Exposure.
- وجود استغلال عام.
- وجود الثغرة داخل CISA KEV.

ويصنف كل CVE إلى:

- Critical
- High
- Medium
- Low
- Info

### 5. واجهة رسومية PyQt5

واجهة التطبيق تحتوي على عدة أقسام:

- Dashboard
- Scan
- Findings
- Report
- Trend
- Settings

كما تحتوي على طبقة HUD Grid اختيارية تظهر أثناء الاستخدام.

### 6. توليد تقارير

يمكن لـ AmanScan توليد تقارير تحتوي على:

- ملخص الهدف.
- معلومات Host وIP.
- الخدمات المكشوفة.
- ملف التعرّض Exposure Profile.
- قائمة CVEs.
- بيانات CVSS.
- بيانات EPSS.
- مؤشرات CISA KEV.
- مؤشرات Public Exploit.
- تحليل AI عند تفعيله.
- إرشادات دفاعية للعلاج والتقليل من المخاطر.

### 7. حفظ سجل الفحوصات

يحفظ التطبيق ملخصات الفحوصات محليًا باستخدام SQLite.  
هذا يسمح لصفحة Trend بعرض النتائج السابقة لهدف معين.

---

## آلية عمل AmanScan

مسار العمل العام داخل التطبيق:

1. المستخدم يدخل هدفًا أو أكثر في صفحة Scan.
2. التطبيق يحمّل الإعدادات المحلية.
3. يتم تطبيع كل هدف.
4. يتم استخراج Host من الرابط أو النص المدخل.
5. يحاول AmanScan حل Host إلى IP.
6. يتم تشغيل مصادر البيانات المفعلة.
7. يتم جمع الخدمات والثغرات وإزالة التكرار.
8. يتم إثراء CVEs من NVD عند التفعيل.
9. يتم إضافة معلومات Exploit Intelligence من EPSS وKEV وSearchsploit وGitHub وShodan.
10. يتم حساب Risk Score وSeverity.
11. يتم توليد تحليل AI اختياري.
12. يتم بناء التقرير.
13. يتم حفظ ملخص الفحص محليًا.

---

## هيكل المشروع

```text
AmanScan/
├── ai/
│   └── analyzer.py
│
├── config/
│   └── config_manager.py
│
├── core/
│   ├── correlator.py
│   ├── epss_client.py
│   ├── exploit_intel.py
│   ├── nvd_client.py
│   ├── risk.py
│   ├── shodan_client.py
│   ├── telemetry.py
│   ├── webcheck_client.py
│   └── zoomeye_client.py
│
├── report/
│   └── report_builder.py
│
├── ui/
│   ├── about_dialog.py
│   ├── icons.py
│   ├── main_window.py
│   ├── overlays.py
│   ├── settings_window.py
│   └── styles.py
│
├── amanscan.py
├── README.md
├── README_AmanScan.md
└── requirements.txt
```

### شرح الملفات المهمة

| الملف | الوصف |
|---|---|
| `amanscan.py` | نقطة تشغيل التطبيق الرئيسية. |
| `ui/main_window.py` | الواجهة الرئيسية، صفحات التنقل، تشغيل الفحص، معاينة التقرير، والتصدير. |
| `ui/settings_window.py` | صفحة الإعدادات الخاصة بمفاتيح API وخيارات التفعيل. |
| `ui/overlays.py` | طبقة HUD Grid المستخدمة داخل الواجهة. |
| `config/config_manager.py` | تحميل وحفظ إعدادات التطبيق المحلية. |
| `core/correlator.py` | المحرك الرئيسي المسؤول عن تشغيل الفحص وربط النتائج. |
| `core/risk.py` | حساب الخطورة، تصنيف الشدة، تحليل الخدمات، وإرشادات العلاج. |
| `core/shodan_client.py` | التكامل مع Shodan وInternetDB. |
| `core/zoomeye_client.py` | التكامل مع ZoomEye. |
| `core/nvd_client.py` | إثراء بيانات CVE وCPE من NVD. |
| `core/epss_client.py` | جلب احتمالية الاستغلال من EPSS. |
| `core/exploit_intel.py` | ربط معلومات الاستغلال من KEV وEPSS وSearchsploit وGitHub ومصادر أخرى. |
| `core/telemetry.py` | تخزين سجل الفحوصات محليًا. |
| `ai/analyzer.py` | تحليل اختياري باستخدام الذكاء الاصطناعي. |
| `report/report_builder.py` | توليد تقرير HTML. |
| `requirements.txt` | مكتبات Python المطلوبة. |

---

## المتطلبات

البيئة المقترحة:

- Python 3.10 أو أحدث
- pip
- Virtual Environment
- Windows أو Linux أو macOS مع دعم PyQt5

مكتبات Python المطلوبة:

```text
PyQt5>=5.15.9
requests>=2.31.0
reportlab>=4.0.0
zoomeye>=3.0.0
openai>=1.0.0
```

---

## التثبيت

### 1. استنساخ المشروع

```bash
git clone https://github.com/abedalrahman-manasrah/AmanScan.git
cd AmanScan
```

### 2. إنشاء بيئة افتراضية

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. تثبيت المتطلبات

```bash
pip install -r requirements.txt
```

---

## تشغيل التطبيق

```bash
python amanscan.py
```

إذا كان جهازك يستخدم `python3` بدل `python`:

```bash
python3 amanscan.py
```

---

## الإعدادات ومفاتيح API

يحفظ AmanScan الإعدادات المحلية في:

```text
~/.config/amanscan/config.json
```

ويحفظ قاعدة بيانات سجل الفحوصات في:

```text
~/.config/amanscan/history.sqlite
```

يمكن ضبط مفاتيح API من صفحة **Settings** داخل التطبيق.

مثال إعدادات:

```json
{
  "shodan_api_key": "YOUR_SHODAN_KEY",
  "zoomeye_api_key": "YOUR_ZOOMEYE_KEY",
  "openai_api_key": "YOUR_OPENAI_KEY",
  "openai_model": "gpt-5",
  "github_token": "YOUR_GITHUB_TOKEN",
  "webcheck_base_url": "http://127.0.0.1:8080",
  "nvd_api_key": "YOUR_NVD_KEY",

  "enable_webcheck": true,
  "enable_shodan": true,
  "enable_zoomeye": true,
  "enable_nvd": true,
  "enable_ai": true,

  "ui_theme": "hud_dark"
}
```

### التكاملات الاختيارية

| التكامل | المطلوب |
|---|---|
| Shodan | مفتاح Shodan API |
| ZoomEye | مفتاح ZoomEye API |
| NVD | مفتاح NVD API اختياري لكنه مفيد |
| OpenAI | مفتاح OpenAI API |
| GitHub PoC Search | GitHub Token اختياري |
| Web-Check | رابط خدمة Web-Check محلية أو خارجية |
| Searchsploit | تثبيت Searchsploit وإتاحته في PATH |

> لا ترفع مفاتيح API أو ملفات الإعدادات المحلية إلى GitHub.

---

## طريقة الاستخدام

1. شغّل التطبيق:

```bash
python amanscan.py
```

2. افتح صفحة **Settings** وأدخل مفاتيح API المطلوبة.

3. انتقل إلى صفحة **Scan**.

4. أدخل الأهداف، كل هدف في سطر:

```text
example.com
https://example.org
8.8.8.8
```

5. اضغط **Start Portfolio Scan**.

6. راقب شريط التقدم ورسائل Log.

7. بعد انتهاء الفحص، راجع:

- **Dashboard** لملخص عام.
- **Findings** للنتائج الفنية.
- **Report** للتقرير النهائي.
- **Trend** لسجل الفحوصات السابقة.
- **Settings** لتعديل التكاملات.

8. صدّر النتائج حسب الحاجة:

- HTML
- PDF
- JSON

---

## نموذج تقييم المخاطر

يستخدم AmanScan درجة خطورة من `0` إلى `100`.

الصيغة الأساسية:

```text
Risk Score = CVSS × EPSS × Exposure
```

ثم يتم تعديل الدرجة بناءً على مؤشرات إضافية:

```text
+8  إذا كان هناك دليل على وجود استغلال عام
+20 إذا كانت الثغرة موجودة في CISA KEV
```

بعد ذلك يتم حصر الدرجة بين `0` و`100`.

### تصنيف الخطورة

| نطاق الدرجة | التصنيف |
|---:|---|
| 85 - 100 | Critical |
| 65 - 84 | High |
| 40 - 64 | Medium |
| 15 - 39 | Low |
| 0 - 14 | Info |

### مؤشر التعرّض Exposure Hint

يقوم AmanScan بتقدير مستوى التعرّض بناءً على الخدمات والمنافذ المكتشفة.  
بعض المنافذ الحساسة ترفع درجة التعرّض أكثر من منافذ الويب العادية.

أمثلة على خدمات حساسة:

| الخدمة | المنفذ |
|---|---:|
| SSH | 22 |
| Telnet | 23 |
| RDP | 3389 |
| MySQL | 3306 |
| PostgreSQL | 5432 |
| Redis | 6379 |
| Elasticsearch | 9200 |
| MongoDB | 27017 |

---

## التقارير والتصدير

يدعم AmanScan تصدير النتائج بعدة صيغ.

### HTML

تقرير قابل للقراءة داخل المتصفح.

### PDF

نسخة PDF من التقرير الحالي.

### JSON

تصدير منظم لنتائج Portfolio Scan.

مثال على بنية JSON:

```json
[
  {
    "target_url": "https://example.com",
    "host": "example.com",
    "ip": "93.184.216.34",
    "services": [],
    "zoomeye_hits": [],
    "cves": [],
    "profiles": {},
    "risk_summary": {
      "exposure_hint_0_15": 0,
      "overall_risk_0_100": 0,
      "counts": {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
      }
    }
  }
]
```

---

## سجل الفحوصات المحلي

يحفظ AmanScan ملخصات الفحوصات محليًا باستخدام SQLite.

يمكن أن يحتوي السجل على:

- وقت الفحص.
- الهدف.
- Host.
- عنوان IP.
- درجة Exposure.
- درجة Overall Risk.
- أعلى CVSS.
- عدد ثغرات KEV.
- عدد الثغرات حسب التصنيف.

تستخدم صفحة **Trend** هذه البيانات لعرض النتائج السابقة.

---

## ملاحظات أمنية وأخلاقية

AmanScan مخصص لـ:

- مراجعة الأصول بشكل دفاعي.
- التقييم الأمني الداخلي.
- مشاريع الأمن السيبراني التعليمية.
- تعلم OSINT واستخبارات الثغرات.
- إعداد تقارير أمنية مصرح بها.

لا تستخدم AmanScan في:

- الفحص غير المصرح.
- استهداف أنظمة لا تملكها.
- جمع معلومات عن أطراف ثالثة دون إذن.
- أي نشاط هجومي أو غير قانوني.
- مخالفة شروط استخدام مزودي API.

---

## حدود المشروع

AmanScan ليس إطار اختبار اختراق كاملًا ولا يغني عن إدارة الثغرات الاحترافية.

من الحدود المحتملة:

- قد تكون بيانات المصادر الخارجية قديمة.
- قد تظهر نتائج False Positives.
- بعض المصادر تحتاج مفاتيح API مدفوعة أو محدودة.
- ربط CVEs يعتمد على جودة بيانات CPE والخدمات.
- تحليل AI يعتمد على جودة البيانات التي تم جمعها.
- بيانات التعرّض السلبية لا تعكس دائمًا الوضع الأمني الداخلي الحقيقي.

---

## استكشاف الأخطاء

### التطبيق لا يعمل

أعد تثبيت المتطلبات:

```bash
pip install -r requirements.txt
```

ثم شغّل:

```bash
python amanscan.py
```

### خطأ في تثبيت PyQt5

جرّب تحديث pip وإعادة تثبيت PyQt5:

```bash
python -m pip install --upgrade pip
pip install --force-reinstall PyQt5
```

### لا تظهر نتائج Shodan

تحقق من:

- إدخال مفتاح Shodan API.
- تفعيل تكامل Shodan.
- توفر Quota في المفتاح.
- صحة الهدف وقدرة النظام على حله إلى IP.

### لا تظهر نتائج ZoomEye

تحقق من:

- إدخال مفتاح ZoomEye API.
- تفعيل تكامل ZoomEye.
- صلاحية المفتاح.
- صحة IP الهدف.

### تحليل AI لا يعمل

تحقق من:

- إدخال مفتاح OpenAI.
- تفعيل AI Analysis.
- اختيار موديل صحيح.
- توفر اتصال بالإنترنت.

### فشل الاتصال بـ Web-Check

تأكد من أن خدمة Web-Check تعمل وأن `webcheck_base_url` يشير للرابط الصحيح.

### Searchsploit لا يعطي نتائج

تأكد من تثبيت Searchsploit:

```bash
searchsploit --help
```

---

## خارطة تطوير مقترحة

أفكار تطوير مستقبلية:

- إضافة صور للواجهة داخل README.
- إضافة Quick Start باللغة الإنجليزية فقط.
- إضافة Docker support.
- إضافة CLI mode.
- إضافة CSV export.
- إضافة Unit Tests لمجلد `core`.
- إضافة GitHub Actions للفحص التلقائي.
- تجهيز ملفات تنفيذية لأنظمة Windows وLinux وmacOS.
- إضافة Plugin System لمصادر OSINT جديدة.
- إضافة مقارنة بين فحصين لنفس الهدف.
- إضافة تنبيهات عند ارتفاع مستوى الخطورة مقارنة بالفحص السابق.
- إضافة ملف `config.example.json`.

---

## الرخصة

لا يظهر ملف رخصة واضح حاليًا.

قبل نشر المشروع أو توزيعه، يفضل إضافة ملف `LICENSE`.

خيارات شائعة:

- MIT License
- Apache License 2.0
- GPL License

---

## المؤلف

مالك المستودع:

```text
ENG: Abed Alrahman Manasrah
Abdulhamid Zaro
```

اسم المشروع:

```text
AmanScan
```

