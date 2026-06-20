# AmanScan

**AmanScan** هو تطبيق سطح مكتب مبني بلغة **Python** وواجهة **PyQt5** لتحليل مستوى التعرّض الأمني للأهداف بشكل دفاعي اعتمادًا على مصادر OSINT وخدمات استخبارات الثغرات.  
يساعد التطبيق فرق الأمن، مسؤولي الأنظمة، والباحثين في الأمن السيبراني على جمع صورة أولية عن الخدمات المكشوفة، الثغرات المرتبطة بها، مستوى الخطورة، ووجود مؤشرات استغلال عامة أو معروفة.

> الغرض من المشروع دفاعي وتعليمي فقط. استخدم AmanScan فقط على الأصول التي تملكها أو لديك تصريح رسمي لاختبارها.

---

## المحتويات

- [نظرة عامة](#نظرة-عامة)
- [الميزات الرئيسية](#الميزات-الرئيسية)
- [آلية العمل](#آلية-العمل)
- [هيكل المشروع](#هيكل-المشروع)
- [المتطلبات](#المتطلبات)
- [التثبيت والتشغيل](#التثبيت-والتشغيل)
- [الإعدادات ومفاتيح API](#الإعدادات-ومفاتيح-api)
- [طريقة الاستخدام](#طريقة-الاستخدام)
- [نموذج تقييم المخاطر](#نموذج-تقييم-المخاطر)
- [التقارير والتصدير](#التقارير-والتصدير)
- [قاعدة بيانات السجل المحلي](#قاعدة-بيانات-السجل-المحلي)
- [ملاحظات أمنية وأخلاقية](#ملاحظات-أمنية-وأخلاقية)
- [حدود المشروع](#حدود-المشروع)
- [خارطة تطوير مقترحة](#خارطة-تطوير-مقترحة)
- [استكشاف الأخطاء](#استكشاف-الأخطاء)
- [الرخصة](#الرخصة)

---

## نظرة عامة

يقوم AmanScan بتنفيذ عملية **Passive Security Exposure Intelligence** على هدف واحد أو عدة أهداف، مثل:

- دومين: `example.com`
- رابط: `https://example.com`
- عنوان IP: `8.8.8.8`

بعد إدخال الأهداف، يجمع التطبيق بيانات من مصادر مختلفة مثل Web-Check، Shodan، InternetDB، ZoomEye، NVD، EPSS، CISA KEV، GitHub PoC، وSearchsploit، ثم يربط النتائج معًا داخل نموذج تقييم مخاطر موحّد.  
يعرض التطبيق النتائج في واجهة رسومية ويتيح تصدير تقرير بصيغ HTML وPDF وJSON.

---

## الميزات الرئيسية

### 1. فحص تعرّض دفاعي Passive

- تحليل الدومين أو عنوان IP.
- محاولة حل اسم النطاق إلى IP.
- تجميع الخدمات والمنافذ المكشوفة من مصادر خارجية.
- تقليل التكرار بين نتائج المصادر المختلفة.

### 2. دعم فحص عدة أهداف

يمكن إدخال أكثر من هدف، كل هدف في سطر مستقل، ثم تشغيل فحص Portfolio Scan لكل الأهداف دفعة واحدة.

### 3. تكامل مع مصادر استخبارات أمنية

يدعم المشروع التكامل مع:

- **Web-Check** لفحص معلومات عامة عن الهدف.
- **Shodan** لجمع معلومات الخدمات المكشوفة.
- **Shodan InternetDB** كإثراء سريع لعناوين IP.
- **ZoomEye** كمصدر إضافي لاستخبارات الخدمات المكشوفة.
- **NVD** لجلب تفاصيل CVE وCVSS وCWE والمراجع.
- **FIRST EPSS** لتقدير احتمالية استغلال الثغرات.
- **CISA KEV** لمعرفة ما إذا كانت الثغرة ضمن الثغرات المستغلة فعليًا.
- **Searchsploit** لاكتشاف وجود Exploit عام محليًا.
- **GitHub** للبحث عن مؤشرات PoC عامة.
- **OpenAI** لتوليد تحليل عربي تنفيذي وفني للنتائج.

### 4. نموذج Risk Scoring

يحسب AmanScan درجة خطورة لكل CVE اعتمادًا على:

- CVSS
- EPSS
- مستوى التعرّض Exposure
- وجود استغلال عام Public Exploit
- وجود الثغرة في CISA KEV

ثم يصنف النتائج إلى:

- Critical
- High
- Medium
- Low
- Info

### 5. واجهة رسومية

واجهة التطبيق تحتوي على أقسام مثل:

- Dashboard
- Scan
- Findings
- Report
- Trend
- Settings

وتتضمن واجهة بأسلوب HUD مع طبقة Grid متحركة اختيارية.

### 6. تقارير احترافية

يمكن توليد تقرير يحتوي على:

- ملخص الهدف.
- ملخص المخاطر.
- تحليل AI باللغة العربية عند تفعيل OpenAI.
- جدول CVEs.
- معلومات CVSS وEPSS وKEV.
- مؤشرات Public Exploit.
- الخدمات المكشوفة.
- نتائج المصادر الخام عند توفرها.

### 7. حفظ سجل الفحوصات

يحفظ التطبيق سجلًا محليًا للفحوصات داخل SQLite، مما يسمح بعرض Trend للنتائج السابقة حسب الهدف.

---

## آلية العمل

مسار العمل العام داخل التطبيق:

1. المستخدم يدخل هدفًا أو أكثر من واجهة Scan.
2. التطبيق يجهز الإعدادات من ملف config المحلي.
3. يتم تطبيع الهدف واستخراج Host وIP إن أمكن.
4. يتم تشغيل مصادر البيانات المفعلة:
   - Web-Check
   - Shodan
   - InternetDB
   - ZoomEye
   - NVD
   - EPSS
   - KEV
   - GitHub PoC
   - Searchsploit
5. يتم دمج الخدمات والثغرات وإزالة التكرار.
6. يتم بناء ملف Risk Summary.
7. يتم توليد تقرير HTML.
8. يمكن تصدير النتائج إلى HTML أو PDF أو JSON.
9. يتم حفظ ملخص الفحص في قاعدة بيانات SQLite محلية.

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
└── requirements.txt
```

### شرح الملفات المهمة

| الملف | الوصف |
|---|---|
| `amanscan.py` | نقطة تشغيل التطبيق، يستدعي واجهة المستخدم الرئيسية. |
| `ui/main_window.py` | الواجهة الرئيسية، صفحات التطبيق، تشغيل الفحص، عرض النتائج، والتصدير. |
| `ui/settings_window.py` | نافذة إعدادات مفاتيح API وخيارات التفعيل. |
| `ui/overlays.py` | طبقة HUD Grid المتحركة داخل الواجهة. |
| `config/config_manager.py` | تحميل وحفظ الإعدادات المحلية داخل مجلد المستخدم. |
| `core/correlator.py` | المحرك المركزي الذي يجمع النتائج من كل المصادر ويحسب المخاطر. |
| `core/risk.py` | نموذج تقييم المخاطر، التصنيفات، وPlaybooks العلاجية. |
| `core/shodan_client.py` | التعامل مع Shodan وInternetDB. |
| `core/zoomeye_client.py` | التعامل مع ZoomEye API. |
| `core/nvd_client.py` | جلب وتحليل بيانات NVD CVE API. |
| `core/epss_client.py` | جلب احتمالية الاستغلال من EPSS. |
| `core/exploit_intel.py` | دمج KEV وEPSS وSearchsploit وGitHub PoC. |
| `core/telemetry.py` | حفظ أحداث API وملخصات الفحص في SQLite. |
| `ai/analyzer.py` | توليد تحليل عربي باستخدام OpenAI عند تفعيل الذكاء الاصطناعي. |
| `report/report_builder.py` | بناء تقرير HTML النهائي. |
| `requirements.txt` | مكتبات Python المطلوبة للتشغيل. |

---

## المتطلبات

يفضل استخدام:

- Python 3.10 أو أحدث
- pip
- بيئة افتراضية Virtual Environment
- نظام تشغيل يدعم PyQt5 مثل Windows أو Linux أو macOS

المكتبات الأساسية الموجودة في `requirements.txt`:

```text
PyQt5>=5.15.9
requests>=2.31.0
reportlab>=4.0.0
zoomeye>=3.0.0
openai>=1.0.0
```

### متطلبات اختيارية

بعض الميزات تحتاج أدوات أو مفاتيح إضافية:

| الميزة | المطلوب |
|---|---|
| Shodan | مفتاح Shodan API |
| ZoomEye | مفتاح ZoomEye API |
| NVD | مفتاح NVD API اختياري لتحسين حدود الطلبات |
| OpenAI | مفتاح OpenAI API لتفعيل التحليل العربي |
| GitHub PoC Search | GitHub Token اختياري |
| Web-Check | تشغيل خدمة Web-Check محليًا أو توفير رابط API |
| Searchsploit | تثبيت Exploit-DB/Searchsploit على الجهاز |

---

## التثبيت والتشغيل

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

### 4. تشغيل التطبيق

```bash
python amanscan.py
```

---

## الإعدادات ومفاتيح API

يحفظ AmanScan الإعدادات في المسار التالي:

```text
~/.config/amanscan/config.json
```

وقاعدة بيانات السجل في:

```text
~/.config/amanscan/history.sqlite
```

يمكن ضبط الإعدادات من نافذة **Settings** داخل التطبيق، أو تعديل ملف `config.json` يدويًا.

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

> لا ترفع ملف `config.json` إلى GitHub لأنه يحتوي مفاتيح API حساسة.

---

## طريقة الاستخدام

1. شغّل التطبيق:

```bash
python amanscan.py
```

2. افتح صفحة **Settings** وأدخل مفاتيح API التي تريد استخدامها.

3. انتقل إلى صفحة **Scan**.

4. أدخل الأهداف، كل هدف في سطر:

```text
example.com
https://example.org
8.8.8.8
```

5. اضغط **Start Portfolio Scan**.

6. راقب التقدم من شريط Progress ومن رسائل Log.

7. بعد انتهاء الفحص:
   - افتح **Findings** لمشاهدة النتائج.
   - افتح **Report** لمشاهدة التقرير.
   - افتح **Trend** لمراجعة السجلات السابقة.
   - صدّر التقرير إلى HTML أو PDF أو JSON.

---

## نموذج تقييم المخاطر

يعتمد AmanScan على نموذج يجمع بين أثر الثغرة واحتمالية استغلالها وسياق التعرّض.

الصيغة العامة المستخدمة:

```text
Risk Score = CVSS × EPSS × Exposure
```

ثم يتم تعزيز الدرجة عند وجود مؤشرات أقوى:

```text
+8  عند وجود Public Exploit
+20 عند وجود الثغرة داخل CISA KEV
```

بعد ذلك يتم ضبط الدرجة بين 0 و100.

### تصنيف الخطورة

| الدرجة | التصنيف |
|---:|---|
| 85 - 100 | Critical |
| 65 - 84 | High |
| 40 - 64 | Medium |
| 15 - 39 | Low |
| 0 - 14 | Info |

### Exposure Hint

يتم حساب مؤشر تعرّض أولي بناءً على نوع وعدد الخدمات المكشوفة.  
على سبيل المثال، بعض المنافذ الحساسة مثل قواعد البيانات أو Remote Access ترفع مستوى التعرّض أكثر من الخدمات العامة.

أمثلة على الخدمات ذات الحساسية العالية:

- SSH: `22`
- Telnet: `23`
- RDP: `3389`
- MySQL: `3306`
- PostgreSQL: `5432`
- Redis: `6379`
- Elasticsearch: `9200`
- MongoDB: `27017`

---

## التقارير والتصدير

يدعم التطبيق تصدير النتائج بالصيغ التالية:

### HTML

تقرير قابل للفتح في المتصفح، يحتوي على التنسيق الكامل والجداول.

### PDF

تصدير التقرير الحالي كملف PDF من داخل الواجهة.

### JSON

تصدير نتائج Portfolio Scan بصيغة JSON لاستخدامها في أدوات أخرى أو أرشفتها.

مثال على محتوى JSON المتوقع:

```json
[
  {
    "target_url": "https://example.com",
    "host": "example.com",
    "ip": "93.184.216.34",
    "services": [],
    "cves": [],
    "risk_summary": {
      "overall": 0,
      "severity_counts": {
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

## قاعدة بيانات السجل المحلي

يستخدم AmanScan قاعدة بيانات SQLite لتخزين ملخصات الفحوصات السابقة.

الجدول الأساسي:

```text
scan_history
```

يحتوي على بيانات مثل:

- تاريخ الفحص
- الهدف
- IP
- Exposure Hint
- Overall Risk
- أعلى CVSS
- عدد ثغرات KEV
- عدد Critical/High/Medium/Low/Info

هذا يسمح لصفحة **Trend** بعرض التغيرات السابقة لكل هدف.

---

## ملاحظات أمنية وأخلاقية

هذا المشروع مخصص للاستخدام الدفاعي فقط.

استخدمه في الحالات التالية:

- تقييم أصولك الشخصية أو أصول شركتك.
- فحص بيئات لديك تصريح رسمي عليها.
- إعداد تقارير دفاعية لفريق الأمن.
- تعليم مفاهيم OSINT وVulnerability Intelligence.

لا تستخدمه في:

- استهداف أنظمة لا تملكها.
- جمع معلومات عن أطراف دون تصريح.
- تنفيذ أي نشاط هجومي أو استغلال غير مصرح.
- تجاوز شروط استخدام مزودي البيانات مثل Shodan أو ZoomEye أو GitHub.

---

## حدود المشروع

AmanScan لا يغني عن اختبار اختراق كامل أو فحص Vulnerability Scanner داخلي.  
هو يقدم صورة OSINT دفاعية مفيدة، لكنه قد يحتوي على:

- نتائج قديمة من مصادر خارجية.
- False Positives.
- نقص في البيانات إذا لم تكن مفاتيح API متوفرة.
- حدود Rate Limit حسب مزود الخدمة.
- اعتماد على جودة CPE mapping عند ربط الخدمات بـ NVD.
- نتائج AI تعتمد على البيانات المتاحة وليست حكمًا نهائيًا.

---

## استكشاف الأخطاء

### التطبيق لا يعمل بعد التشغيل

تأكد من تثبيت المتطلبات:

```bash
pip install -r requirements.txt
```

ثم شغّل:

```bash
python amanscan.py
```

### خطأ متعلق بـ PyQt5

على بعض الأنظمة قد تحتاج تثبيت متطلبات إضافية لواجهة Qt.  
جرب تحديث pip ثم إعادة التثبيت:

```bash
python -m pip install --upgrade pip
pip install --force-reinstall PyQt5
```

### لا تظهر نتائج Shodan

تحقق من:

- إدخال مفتاح Shodan API.
- تفعيل خيار Shodan من Settings.
- صحة الهدف.
- عدم انتهاء حدود API.

### لا تظهر نتائج ZoomEye

تحقق من:

- إدخال مفتاح ZoomEye.
- تفعيل ZoomEye.
- عدم وجود Rate Limit أو WAF block.
- صحة صيغة الهدف.

### تحليل AI لا يعمل

تحقق من:

- إدخال مفتاح OpenAI.
- تفعيل خيار AI.
- اختيار موديل صحيح.
- توفر اتصال إنترنت.

### Web-Check يعطي Connection Refused

هذا يعني غالبًا أن خدمة Web-Check غير مشغلة على العنوان المحدد.  
إما شغّل الخدمة، أو عطّل Web-Check من Settings.

### Searchsploit لا يعطي نتائج

تأكد من تثبيت Searchsploit وأن الأمر متاح في PATH:

```bash
searchsploit --help
```

---

## خارطة تطوير مقترحة

أفكار يمكن إضافتها لاحقًا:

- إضافة README باللغة الإنجليزية.
- إضافة Screenshots للواجهة.
- إضافة Dockerfile.
- إضافة Tests لوحدات `core`.
- إضافة CLI mode للفحص بدون واجهة رسومية.
- إضافة Export إلى CSV.
- إضافة نظام Plugins لمصادر OSINT جديدة.
- إضافة صفحة مقارنة بين فحصين لنفس الهدف.
- إضافة تنبيهات عند ارتفاع مستوى المخاطر مقارنة بالفحص السابق.
- إضافة Packaging لإنتاج ملف تنفيذي Windows/Linux/macOS.
- إضافة ملف `.env.example` أو `config.example.json`.
- إضافة GitHub Actions لفحص الكود تلقائيًا.

---

## الرخصة

لا يظهر داخل المشروع ملف رخصة واضح حاليًا.  
قبل نشر المشروع أو السماح للآخرين باستخدامه، يفضل إضافة ملف `LICENSE`.

اقتراح شائع للمشاريع مفتوحة المصدر:

- MIT License للمشاريع التعليمية والمفتوحة.
- Apache-2.0 إذا أردت حماية أوضح بخصوص براءات الاختراع.
- GPL إذا أردت إلزام المشاريع المشتقة بالبقاء مفتوحة المصدر.

---

## تنبيه حول الأسرار

تأكد من إضافة الملفات التالية إلى `.gitignore` إن لم تكن موجودة:

```gitignore
# Python
__pycache__/
*.pyc
.venv/
venv/

# Local config and secrets
config.json
.env
*.sqlite
*.db

# Reports
*.html
*.pdf
*.json

# OS
.DS_Store
Thumbs.db
```

---

## المؤلف

تم تطوير AmanScan كمشروع Python Desktop Security Exposure Intelligence.

Repository owner:

```text
abedalrahman-manasrah
```
