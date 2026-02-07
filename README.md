============================================================
        ADVANCED PROXY INTELLIGENCE SCANNER
============================================================

An advanced, high-performance proxy scraping, checking, and
intelligence tool built for serious use cases:
Pentesting, OSINT, Scraping, Automation, and Privacy Testing.

This is NOT a basic “alive/dead” proxy checker.
This tool analyzes, benchmarks, classifies, and stores proxies
with real technical depth.

------------------------------------------------------------
FEATURES
------------------------------------------------------------

[1] PROXY SCRAPING
- Scrapes proxies from 30+ reliable sources
- Supports HTTP / SOCKS4 / SOCKS5
- Auto-discovery of new sources from GitHub
- Duplicate removal
- Optional proxy rotation while scraping

[2] HIGH-SPEED CONCURRENT CHECKING
- Multi-threaded proxy checking (hundreds of threads)
- Smart timeout handling
- Accurate live/dead detection

[3] PROXY INTELLIGENCE (OSINT)
- Country & Country Code
- City
- ISP
- ASN
- Residential vs Datacenter detection
- Latency measurement (ms)

[4] ANONYMITY LEVEL DETECTION
- ELITE
- ANONYMOUS
- TRANSPARENT
- Header-based detection (X-Forwarded-For, Via, etc.)

[5] GOOGLE ACCESS TEST
- Detects:
  PASS (clean access)
  CAPTCHA
  BLOCKED
- Critical for scraping and automation

[6] SPEED BENCHMARK
- Real download test (1MB)
- Speed categories:
  ULTRA
  FAST
  MEDIUM
  SLOW

[7] SSL / TLS SUPPORT CHECK
- Tests HTTPS compatibility
- Detects supported TLS version
- Identifies insecure proxies

[8] BLACKLIST CHECK
- IP reputation check via GetIPIntel
- Detects burned or suspicious proxies

[9] OPEN PORT SCANNING
- Scans common ports:
  21, 22, 23, 80, 443, 3128, 8080, 8888

[10] SQLITE DATABASE
- Persistent storage of live proxies
- Full scan history
- Track first seen / last checked
- Statistics and analytics

[11] EXPORT OPTIONS
- TXT (normal / proxychains format)
- JSON
- CSV
- GeoJSON (map visualization)
- Country-based filtering

[12] GEOJSON MAP EXPORT
- Visualize proxies on a world map
- Compatible with geojson.io

[13] TELEGRAM NOTIFICATIONS
- Send scan results automatically
- Send statistics
- Send proxy files directly

------------------------------------------------------------
OUTPUT EXAMPLES
------------------------------------------------------------

Normal format:
socks5://1.2.3.4:1080 | US | Comcast | DC | 120ms | ELITE | G:PASS | 12.4Mbps | ULTRA | SSL:TLS1.3

Proxychains format:
socks5 1.2.3.4 1080

------------------------------------------------------------
REQUIREMENTS
------------------------------------------------------------

Python 3.9+

Required libraries:
pip install requests colorama python-telegram-bot

------------------------------------------------------------
USE CASES
------------------------------------------------------------

- Web Scraping
- OSINT
- Penetration Testing
- Privacy Analysis
- Automation Bots
- Proxy Pool Building
- Research & Analysis

------------------------------------------------------------
DISCLAIMER
------------------------------------------------------------

This tool is for educational and research purposes only.
You are fully responsible for how you use it.

============================================================
============================================================

============================================================
        ماسح وتحليل البروكسيات المتقدم
============================================================

أداة احترافية عالية الأداء لسحب، فحص، تحليل، وتصنيف البروكسيات.
موجهة للاستخدام الجاد في:
الاختبارات الأمنية، OSINT، السكربتات، الأتمتة، والخصوصية.

هذه ليست أداة “يشتغل أو لا”.
هذه منصة تحليل بروكسيات متكاملة.

------------------------------------------------------------
المميزات
------------------------------------------------------------

[1] سحب البروكسيات
- سحب من أكثر من 30 مصدر موثوق
- دعم HTTP / SOCKS4 / SOCKS5
- اكتشاف مصادر جديدة تلقائيًا من GitHub
- إزالة التكرار
- دعم Proxy Rotation أثناء السحب

[2] فحص عالي السرعة
- فحص متوازي بعدد Threads كبير
- Timeout ذكي
- كشف دقيق للبروكسيات الحية والميتة

[3] ذكاء البروكسي (OSINT)
- الدولة + الكود
- المدينة
- مزود الخدمة ISP
- ASN
- تحديد Residential أو Datacenter
- قياس زمن الاستجابة (ms)

[4] تحليل مستوى التخفي
- ELITE
- ANONYMOUS
- TRANSPARENT
- تحليل Headers حقيقي

[5] اختبار Google
- PASS (يعمل طبيعي)
- CAPTCHA
- BLOCKED
- مهم جدًا للـ Scraping

[6] اختبار السرعة
- تحميل فعلي (1MB)
- تصنيف:
  ULTRA
  FAST
  MEDIUM
  SLOW

[7] فحص SSL / TLS
- دعم HTTPS
- كشف إصدار TLS
- تحديد البروكسيات غير الآمنة

[8] فحص القوائم السوداء
- كشف IP المحظور أو المشبوه

[9] فحص المنافذ المفتوحة
- أشهر المنافذ: 21, 22, 80, 443, 8080…

[10] قاعدة بيانات SQLite
- تخزين البروكسيات الحية
- سجل كامل للفحوصات
- إحصائيات دقيقة

[11] التصدير
- TXT
- JSON
- CSV
- GeoJSON
- فلترة حسب الدولة

[12] خريطة جغرافية
- عرض البروكسيات على خريطة العالم

[13] إشعارات تيليجرام
- إرسال النتائج تلقائيًا
- إرسال الملفات

------------------------------------------------------------
تنبيه
------------------------------------------------------------

الأداة للاستخدام التعليمي والبحثي فقط.
أي استخدام غير قانوني هو مسؤوليتك الكاملة.

------------------------------------------------------------
الخلاصة
------------------------------------------------------------

هذه ليست أداة عادية.
هذه أداة للناس اللي تعرف وش تسوي.

إذا فاهم → بتطلع كنز.
إذا مو فاهم → بتتعلم بالقوة.

============================================================
