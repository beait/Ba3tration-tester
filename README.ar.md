<div align="center">

# 🛡️ Ba3tration-tester

**اختبر تطبيقك من كل زاوية: تجربة المستخدم والأمان، بضغطة واحدة.**

وظيفي · كود (SAST) · تطبيق حي (DAST) · تقرير موحّد على **OWASP Top 10:2025**

[English](README.md) · العربية

</div>

## ثلاثة محركات في تشغيل واحد

| المحرك | يفحص | الأداة | الملف |
|---|---|---|---|
| 🧭 وظيفي | كراش، تدفقات مكسورة، RTL، ترجمات، خط كبير، وضع داكن | مختبِرون أذكياء على محاكيات | `agent-testers.yml` |
| 🧬 الكود | حقن، صلاحيات ناقصة، أسرار مكتوبة في الكود | Semgrep + SemSec | `security-sast.yml` |
| 🛡️ التطبيق الحي | رؤوس الأمان، إعدادات خاطئة، ثغرات الويب الظاهرة من الخارج | OWASP ZAP | `security-dast.yml` |

`ba3tration.yml` يشغّل الثلاثة معًا. كل محرك يعمل أيضًا وحده من ملفه.

## التشغيل

```powershell
gh workflow run ba3tration.yml                                             # الثلاثة بالإعدادات الافتراضية
gh workflow run ba3tration.yml -f engines=security -f code_repo=owner/app  # الأمان فقط، على كود تطبيقك
gh workflow run ba3tration.yml -f engines=functional                       # المختبِرون فقط
gh run watch
.\collect.ps1 <run id>             # على ويندوز. على ماك ولينكس: bash scripts/collect.sh <run id>
```

`collect.sh` يفك التشفير على جهازك ويكتب في `runs/<id>/`:

- `SUMMARY.md`: ملخّص المختبِرين.
- `BA3TRATION-REPORT.md`: التقرير الموحّد، النتائج الأمنية تحت تصنيفات OWASP Top 10:2025 ثم الملخّص الوظيفي.
- `BA3TRATION-REPORT.txt`: نفس التقرير كملف نصي عادي، يُفتح في Notepad أو يُرسل في بريد.

## الإعداد

1. مرة واحدة: `.\setup.ps1`. يفحص البرامج المطلوبة ويثبّت الناقص بعد سؤالك، ثم مفتاح التشفير، وتوكن Claude أو مفتاح Anthropic، ثم يسأل عن حسابات المختبِرين.
   في أي وقت: `.\check.ps1` يقول هل كل ما تحتاجه الأداة موجود على جهازك وفي الريبو، ويثبّت الناقص (Git و GitHub CLI و Python).
   حسابات تجريبية للمختبِرين، حساب لكل دور، تُكتب لهم في شاشة الدخول ولا يرونها: `python scripts\accounts.py set`. التفاصيل في [docs/test-accounts.md](docs/test-accounts.md).
2. فحص الكود لريبو خاص: سر `SOURCE_REPO_TOKEN` بصلاحية قراءة فقط.
3. فحص التطبيق الحي: سر `STAGING_URL`، وملف على موقعك في `/.well-known/ba3tration.txt` فيه سطر
   `ba3tration-site-verification=<owner>/<repo>`. التفاصيل في [docs/security-scan.md](docs/security-scan.md).

من غير الخطوة 3 يتخطّى التشغيل الكامل فحص التطبيق الحي بتحذير، ويكمل الباقي.

## سكيل لأي مساعد برمجة

`skills/ba3tration-tester/SKILL.md` ملف واحد بصيغة Agent Skills المفتوحة، يعمل كما هو مع Claude Code و Codex وأي مساعد يقرأ `SKILL.md`: يركّب الأداة على تطبيقك، يشغّلها، ويقرأ لك التقرير.

```bash
bash scripts/install_skill.sh          # للاثنين: ‎~/.claude/skills و ‎~/.agents/skills
bash scripts/install_skill.sh codex    # أو واحد فقط: claude أو codex
```

المختبِرون أنفسهم على سيرفرات GitHub يعملون بـ Claude Code افتراضيًا، أو بأي API متوافق عبر `llm_base_url`، أيًّا كان المساعد الذي يشغّل السكيل.

## القواعد

- **بالطلب فقط.** لا شيء يعمل في الخلفية.
- **لا فحص حي بدون إذن الموقع.** الموقع يسمّي هذا الريبو في ملف الإثبات، والفحص النشط يحتاج `i_am_authorized=yes` وبيئة اختبار.
- **النتائج مشفّرة.** لا يظهر في سجل GitHub أي نتيجة، والمفتاح الخاص على جهازك فقط.
- **النتائج خيوط للمراجعة.** الفحص الحي يعمل بدون تسجيل دخول، وعزل بيانات الشركات يحتاج مراجعة يدوية.

---

<div align="center">
<sub>مبني على <a href="https://github.com/pierridotite/mobile-agent-testers">mobile-agent-testers</a> (MIT، وشرحه الكامل في <a href="TESTERS.md">TESTERS.md</a>)،
وقواعد <a href="https://github.com/RobustaStudio/semsec">SemSec</a> (MIT)، و<a href="https://www.zaproxy.org/">OWASP ZAP</a>.</sub>
</div>
