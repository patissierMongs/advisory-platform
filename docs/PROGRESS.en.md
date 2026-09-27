# Progress Record

[한국어](PROGRESS.md) | **English**

## Final goal

Handle the full lifecycle of a security advisory PDF (Portable Document Format) received from agencies such as the National Intelligence Service or supervising agencies in one system: CVE (Common Vulnerabilities and Exposures) extraction → local CVE DB (database) lookup → asset matching → per-department dispatch → remediation reply tracking. It must install, run and operate on an air-gapped network with no internet, and let a single security operator process advisories without repetitive manual work.

## Current implementation status

Verified on 2026-09-27 by reading the code, running `pytest tests` (334 passed) and `smoke_test.py` (74 passed), and starting the server with `ADVISORY_SEED=true` to walk through STEP 2-4 in a browser.

| Feature | Status | Code evidence |
|---|---|---|
| PDF upload and regex CVE extraction (normalizes spacing/separator variants) | Implemented | `app/core/extract.py`, `app/routers/advisories.py` |
| Table-first product / affected version / fixed version extraction (coordinate-based table rebuild) | Implemented | `app/core/pdf_tables.py`, `app/core/product_extract.py` |
| Manual CVE/product add, edit and re-extract | Implemented | `app/routers/advisories.py` (`POST /advisories/{id}/cves`, etc.) |
| Original PDF viewer with CVE highlights | Implemented | `app/core/pdf_render.py`, `app/routers/advisories.py` (`/pdf-view`) |
| CVE feed import (NVD (National Vulnerability Database) 1.1/2.0 JSON (JavaScript Object Notation), CSV (Comma-Separated Values), KrCERT (Korea Computer Emergency Response Team) JSON, gzip) with validate-then-apply | Implemented | `app/core/feeds.py`, `app/routers/cve_feeds.py` |
| Re-processing unfinished advisories after a feed is applied | Implemented | `app/core/advisory_ops.py` |
| Server-side gate blocking matching while CVEs are missing (409) | Implemented | `app/routers/matches.py` |
| Asset register Excel import (preview, column mapping, multi-sheet, custom fields) | Implemented | `app/core/assets_import.py`, `app/routers/assets.py` |
| Product normalization, version comparison, asset matching | Implemented | `app/core/normalize.py`, `app/core/versioning.py`, `app/core/matching.py` |
| False-positive exclusion, suggested again on later advisories | Implemented | `app/core/exclusions.py`, `app/routers/remediation.py` (`/exclusion-rules`) |
| Per-department messages, SMTP (Simple Mail Transfer Protocol) mail, generic messenger/groupware webhooks, idempotency | Implemented | `app/core/notify.py`, `app/core/groupware.py`, `app/routers/notifications.py` |
| Remediation replies (done / in progress / not possible) and evidence upload | Implemented | `app/core/remediation.py`, `app/routers/notifications.py` |
| Excel and HTML (HyperText Markup Language) reports | Implemented | `app/core/reports.py`, `app/routers/remediation.py` |
| Due-date reminders | Partial | `app/core/remediation.py` (`due_reminders`), `POST /advisories/{id}/remind` — due list and manual send only; no scheduled automatic reminders |
| Internal board (no-login read, comments, per-asset replies, evidence) | Implemented | `app/routers/board.py`, `web/public/board.html` |
| Dispatch history / remediation console (by advisory and by department, resend to non-responders) | Implemented | `app/routers/history.py`, `web/admin/history.html` |
| Dashboard | Implemented | `app/routers/dashboard.py` |
| Admin login, forced first password change, CSRF (Cross-Site Request Forgery), login lockout | Implemented | `app/auth.py`, `app/routers/auth.py`, `web/public/login.html` |
| HMAC (Hash-based Message Authentication Code) signature check on the groupware reply webhook | Implemented | `app/routers/webhooks.py` |
| Audit log (activity history) | Implemented | `app/audit.py`, `app/routers/audit.py` |
| NTFS (New Technology File System) ACL (Access Control List) on the `data` folder | Implemented (Windows only; verified here by unit tests only) | `app/core/winacl.py`, `scripts/harden_data_acl.bat` |
| Start scripts installing from offline wheels | Implemented | `start.sh`, `start.bat`, `scripts/prepare_offline.*` |
| Windows all-in-one bundle (Python 3.12/3.13, offline build, zip/7z split) | Implemented (build not executed in this environment) | `build_allinone.py`, `scripts/collect_offline_bundle.py` |
| NVD sync PowerShell tool | Implemented (separate tool; its output is uploaded through the UI (user interface)) | `nvd_powershell_sync/` |
| Automatic CVE feed sync inside the app | Not started | Only the label "매일 06:00 (NVD)" (daily 06:00) exists in `web/admin/app.dc.html`; the server has no scheduler |
| OCR (Optical Character Recognition) for scanned (image) PDFs | Not started | Stated as out of scope in a comment in `app/core/extract.py` |
| Design-system bundle regeneration | Partial | `ds-bundle/` output exists, but `.ds-build/build.mjs` still reads pre-move paths (`web/vendor/`, `web/app.dc.html`) |
| Browser E2E (end-to-end) tests and CI (continuous integration) | Not started | Only planned in `docs/testing-guide.md`; no browser tests under `tests/` |

## Work history

Commit dates from `git log`, converted to KST (Korea Standard Time, Asia/Seoul). Commits were stored with a mix of +0900 and +0000 offsets; all were converted to KST.

| Date (KST) | Main work |
|---|---|
| 2026-06-18 | Initial commit (FastAPI backend wired to the frontend), bulk CVE feed upsert and gzip support, LLM (large language model) extraction layer removed in favor of regex-only extraction |
| 2026-06-19 | Internal board (department filter, search, original PDF, evidence), three dispatch-history mockups and the master-detail console (`/admin/history`), NVD sync tool, `start.bat` fixes, port-scan tool experiment |
| 2026-06-20 to 06-21 | Port-scan feature fully rolled back (split into a separate project), dispatch history rework, due-date / receive-channel extraction, code review fixes, operations prep |
| 2026-06-22 to 06-24 | Security review report, removal of internet dependencies from the run path, all-in-one bundle hardening, free-form asset import column mapping, NVD sync resilience |
| 2026-07-02 to 07-07 | QA (quality assurance) testing guide, restored features lost in a branch merge, 27 real-world scenario checks with fixes |
| 2026-07-20 to 07-25 | Major overhaul of the extraction engine, in-field correction and per-asset remediation rate; NVD 1.1 yearly dump support; feed-to-extraction dictionary sync; follow-up security fixes (stored XSS (cross-site scripting), etc.); version-matching false-positive fixes |
| 2026-08-06 | Admin auth (password hashing, sessions, CSRF, lockout), webhook HMAC, full admin API (application programming interface) gate, evidence upload hardening, NTFS ACL, login screen, table-based product/version extraction, all-in-one bundle for Python 3.12/3.13 with offline build and split options |
| 2026-09-27 | Documentation cleanup: old README moved to `docs/상세_운영_가이드.md`, Korean/English READMEs with screenshots, and this progress record added |
