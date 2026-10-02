# UNMASK CLI — compressed blueprint

Everything the UNMASK engine does, reduced to the rules, numbers and formats needed to rebuild it as a
terminal tool (Kali-style: one binary, subcommands, pipes, no browser). Web-only concerns (sessions,
htmx, themes, notifications, share links) are listed only where a CLI needs a counterpart.

Notation: **rel** = source reliability (Admiralty A–F), **p** = prior confidence that the finding is the
subject, **fc** = per-field confidence dict, `→` = produces.

---

## 0. TL;DR

```
targets (username|email|domain|phone|ip|name|image) + context tags
  → tools (26 adapters: CLI binaries + HTTP APIs), throttled, sandboxed, proven-non-empty
  → page check of every account hit (verified / unverified / rejected→dropped)
  → normalise → auto-merge identical values → link & suggest (rules, fuzzy, embeddings)
  → score (prior × reliability × rarity × site record, then evidence shrinks the doubt)
  → evidence lines for/against → analyst decides (confirm / not them / merge / split)
  → pivots (new findings feed new tool runs, depth ≤ 2, budget 20)
  → export (CSV / JSON / STIX 2.1 / Markdown report / graph)
```

Design rules worth keeping: an empty result must be *proven* empty; nothing is auto-confirmed;
only identical canonical values merge automatically; every fetch of a third-party page is done by the
tool, never the analyst's browser; every action is audited.

---

## 1. CLI surface (proposed)

Binary `unmask`. Global flags: `--db PATH` (default `~/.local/share/unmask/unmask.db`),
`--json` (NDJSON on stdout), `-q/--quiet`, `--no-color`, `--proxy URL`, `-v` (progress on stderr).

| Command | Does |
|---|---|
| `unmask init` | create store, generate keys (§3), first-run terms acknowledgement |
| `unmask doctor` | config problems, keys present, which tools are installed/configured, store reachable |
| `unmask case new NAME --auth "NOTE" --lawful-basis -t username:jdoe -t email:j@x.io [--tags a,b] [--template T] [--depth quick\|deep] [--retention 90]` | create case (§2 rules) |
| `unmask case ls / show CASE / rm CASE` | list, summary (counts per band, last run), delete (audited) |
| `unmask scan CASE [--tools a,b] [--depth quick\|deep] [--no-pivot] [--follow]` | run all applicable tools; `--follow` streams per-tool progress |
| `unmask run username:jdoe [--tools …] [--tags …]` | one-shot: in-memory case, print findings, nothing stored (still requires `--auth`) |
| `unmask stop CASE` | cancel active run, keep results |
| `unmask findings CASE [--show best\|all\|confirmed\|dismissed\|undecided] [--type T] [--min 0.45] [--q TEXT]` | table or NDJSON |
| `unmask show CASE FINDING` | evidence card (§9): profile, excerpt, ✓/✗ lines, links, score breakdown |
| `unmask review CASE [--all]` | interactive queue: `y` same person, `n` different person, `p` not a real profile, `b` bot/spam, `s` skip, `u` undo |
| `unmask confirm\|dismiss [--reason R]\|restore CASE FINDING` | decisions (rescore after confirm) |
| `unmask merge CASE A B` / `split CASE MEMBER` | manual merge / undo merge (adds `not_same`) |
| `unmask suggestions CASE` / `accept\|reject CASE REL` | possible-duplicate queue |
| `unmask graph CASE --dot\|--json [--all]` | graph export (§12) |
| `unmask export CASE csv\|json\|stix\|md [--scope visible\|confirmed\|all] [-o FILE]` | §12 |
| `unmask snapshot CASE FINDING` / `snapshot verify CASE` | capture page evidence, re-hash stored captures |
| `unmask tools [ls\|health [TOOL]\|enable T\|disable T\|reset T]` | status table, health checks, circuit breaker |
| `unmask keys [ls\|set NAME\|rm NAME\|test NAME]` | API keys (§13), stored encrypted; `set` reads from stdin |
| `unmask watch CASE weekly\|monthly\|off` / `unmask tick` | watch mode; `tick` = one scheduler pass (cron it) |
| `unmask purge [--dry-run]` | retention purge (§11) |
| `unmask eval FILE [--tools …] [--json OUT]` | precision/recall harness (§14) |
| `unmask audit CASE` | access log |

Output conventions: data → stdout, progress/warnings → stderr. One finding per line:
`[LIKELY 0.87] ✓6 ✗0  account  https://github.com/jdoe  (sherlock,maigret) page✓`.
Strength tags: `TARGET`, `CONFIRMED`, `LIKELY`, `POSSIBLE`, `UNLIKELY`, `NOT-THEM`.
Exit codes: 0 ok, 1 error, 2 bad usage/validation, 3 partial run (some tools failed), 4 nothing to do,
130 interrupted.

---

## 2. Guardrails (keep them in the CLI)

| Guardrail | Rule |
|---|---|
| Lawful basis | case needs `authorization_note` (non-blank) **and** `lawful_basis_confirmed=true` (timestamped); enforced in validation and as DB CHECKs |
| Terms | `TERMS_VERSION = "2026-09-29"`; require acknowledgement (two statements: terms + "I am responsible for lawful use") when it changes |
| Audit | every create/scan/view/export/decision/purge → `access_log(action, case, detail, ts)`; audit rows survive case deletion (case id copied into detail) |
| Sandbox | tool subprocesses: no shell, temp cwd, scrubbed env (§4.2), keys via 0600 files never argv |
| Rate limits | per-tool slots + delay, global subprocess cap, verification caps (§5, §6) |
| SSRF (snapshots) | http/https only, ports {default,80,443,8080,8443}, every resolved IP `is_global`, re-checked per redirect, ≤5 redirects, ≤2 MB, 15 s |
| Pivots | never into shared mail/platform domains (§10) |
| Exports | CSV formula-injection guard; STIX marked TLP:AMBER |
| Not done (gaps) | target sites' robots.txt is not consulted; DNS rebinding between check and fetch (use the proxy) |

---

## 3. Data model

All ids UUID; timestamps UTC. **Bold** = encrypted at rest.

| Table | Columns |
|---|---|
| case | id, name(≤200), authorization_note, lawful_basis_confirmed(+_at), notes, analyst_assessment(+_updated_at), owner, watch_config `{enabled,frequency,next_run_at,auto_pivot}`, retention_days=90 (>0), permanently_active, disabled_tools[], last_reviewed_run_number, template, created/updated |
| target | id, case_id, **value**, value_digest, type, context_tags[] |
| run | id, case_id, run_number (unique per case), status, started/completed, tools_included/completed/failed[], failure_details{tool→reason, `_note`→…}, jobs_total/done, triggered_by, priority |
| entity | id, case_id, run_id, type, **value**, value_digest, **attributes**{}, source_tool, confidence∈[0,1], field_confidence{}, source_reliability A–F, tag_match_score, first_seen, last_verified, confirmed_flag, dismissed_flag, dismiss_reason, verification(verified\|unverified\|null), site_host, is_seed, merged_into_id |
| observation | entity_id, run_id, source_tool, confidence, attributes_digest (sha256 sorted JSON), observed_at — unique (entity, run, tool) |
| relation | id, case_id, entity_a, entity_b, relation_type, source_tool, **match_explanation**, confidence, created_by (`engine` \| `analyst:<who>` \| tool) |
| pivot_log | case_id, run_id, triggering_entity, triggered_tool, rule_matched (or skip reason), confidence_at_trigger |
| tool_config | tool (pk), enabled, max_concurrent=3, delay_ms=500, consecutive_failures, circuit_open, last_success/failure(+reason), last_health_check, last_health_ok |
| access_log | case_id, actor, action, detail{}, ts |
| snapshot | case_id, entity_id, **url**, **final_url**, status, content_type, sha256, size, truncated, **title**, **body_b64** |
| secret | name (pk), **value**, updated_at — overrides the env var of the same setting |

Enumerations:
- Target types: `username email domain phone ip name image`.
- Entity types (emitted): `username email account registration breach name domain hostname ip phone web_mention image other`.
- Relation types: **corroborating** = `shares_handle profile_name_match email_at_domain breach_associated profile_links_to`;
  structural = `has_account registered_on exposed_in subdomain resolves_to resolved_to reverse_dns mentioned_on mentioned_with committed_as has_email has_profile uses_handle controls_domain registered_by archived_page spiderfoot_link guessed_email`;
  analyst/engine = `possible_same same_as not_same`.
- Run status: `queued running completed partial failed cancelled`. Trigger: `manual(prio 0) pivot_chain(5) watch_mode(10) health_check(20)`.
- Dismiss reasons: `different_person not_a_profile bot_or_spam other`.

Crypto:
- Encryption: MultiFernet over comma-separated `UNMASK_DATA_KEYS` (first encrypts, all decrypt, `rotate` re-encrypts). Text stored `enc:v1:<token>`; JSON stored `{"_enc":"enc:v1:<token>"}`.
- Blind index (dedupe without decrypting): `digest(kind, v) = HMAC_SHA256(UNMASK_INDEX_KEY, kind + "\x00" + NFKC(v).strip().casefold())` hex.
- `gen-keys`: data key = Fernet key; index key = `token_urlsafe(48)`.

---

## 4. Tools

### 4.1 Adapter contract

```
Adapter: name, label, input_types[], description, enabled_by_default=True,
         health_check_target=None, timeout_seconds=None(→300), verify_accounts=False, speed=fast|slow
  configured() -> None | "reason it can't run"
  run(value, tags) -> [RawResult(tool, target_value, payload, fetched_at)]
  parse(raw) -> [Candidate(type, value, attributes{}, rel="F", p=0.5, fc{}, relation_type, relation_explanation)]
  health_check() -> (ok, detail)          # default: run(health_target) and ≥1 candidate
Errors: AdapterError (counts toward breaker) ⊃ SignatureMismatch (output isn't a genuine finished run)
        InvalidTarget (bad input; does NOT count toward breaker)
```
Slow tools (skipped by `--depth quick`): maigret, theharvester, amass, spiderfoot.

Validators:

| Input | Rule |
|---|---|
| username | strip, strip leading `@`; `^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$` |
| email | no leading `-`; `^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9\-]{1,63})+$` |
| domain | lower, strip trailing `.`, no leading `-`; `^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$` |
| ip | parses and `is_global` (SpiderFoot accepts any IP or a domain) |
| phone | keep `[\d+]`, drop leading `+`, 7–15 digits |
| search text | remove `"`, collapse spaces, 1–200 chars |
| case targets (form) | email `^[^@\s]+@[^@\s]+\.[^@\s]+$`; phone `^\+?[0-9 ()\-.]{6,20}$`; value ≤512; tags: comma split, ≤64 chars each, ≤20, case-insensitive dedupe |

### 4.2 Subprocess sandbox
- Binary lookup: `$UNMASK_TOOLS_BIN/<name>` if executable, else `PATH`; missing → `AdapterError("<name> is not installed")`.
- Global cap: `UNMASK_TOOL_PROCS=3` processes at once (waiting doesn't count toward the timeout).
- `exec` (no shell), stdin=/dev/null, cwd = fresh temp dir; input files written `O_EXCL` mode 0600.
- Env = only `PATH, HOME=<tmp>, LANG=C.UTF-8, PYTHONUNBUFFERED=1, NO_COLOR=1` + passthrough `HTTP(S)_PROXY, NO_PROXY, SSL_CERT_FILE, REQUESTS_CA_BUNDLE` + per-tool proxy (§13).
- Timeout → kill, `AdapterError("<tool> timed out after Ns")`; cancel → kill and wait.
- Output: stdout, stderr, collected globs (no symlinks) each capped 8 MiB, utf-8 `replace`; strip ANSI `\x1b\[[0-9;?]*[A-Za-z]|\x1b\]8;;.*?\x1b\\|\r`.
- Non-zero exit → `AdapterError("<tool> exited with code N: <last stderr/stdout line[:300]>")`.

### 4.3 HTTP helpers
- API client: UA `unmask-osint/0.2`, `Accept: application/json`, no redirects, pooled (20 conns / 10 keep-alive / 30 s) per timeout.
- `get_json`: non-200 → AdapterError; strict mode requires `json` content-type else SignatureMismatch; unparsable → SignatureMismatch.
- `fetch_json` (lookups, 30 s): status in `missing` (default 404) → `None` = no record; 401/403 → "key rejected"; 429 → "rate-limited"; other non-200 → error; bad JSON → SignatureMismatch.
- `api_account(...)` → account, rel B, p 0.55, fc `{exists: .95 if verified else .7, same_person: p}`, attrs `site,url,username,host,profile{},preview{title,links,emails},verification`.
- `linked(...)` → B/0.75 verified if proven, else C/0.6. `enrich(kind,value,tool,details)` → F/0 (adds details to an existing finding, never scores).
- Text link scrape: `https?://[^\s"'<>)]+` (≤10, trailing `.,;` stripped), emails ≤5.

### 4.4 Catalogue (26)

Subprocess tools:

| Tool | In | Command | Needs | Emits (type · relation · rel · p) | Page check | Timeout | Proof of a real run (else SignatureMismatch) |
|---|---|---|---|---|---|---|---|
| sherlock | username | `sherlock --print-all --no-color --local --timeout 10 [--site S]… -- USER` | – | account · has_account · C · .4; fc exists .7 | yes | 300 | banner `[*] Checking username X on:`; `[*] Search completed with N results`; N == count of `[+]` lines; ≥1 site checked; errored/checked ≤ 0.5 |
| maigret | username | `maigret --no-color --no-progressbar --print-errors --no-recursion --timeout 10 -J ndjson -fo out [--site S… \| --top-sites 200] -- USER` | – | account · has_account · C · .45 if profile ids else .4; profile ⊂ {fullname,name,bio,location,country,city,website,links,image,created_at}, tags | yes | 900 | banner + `Starting a search on top N sites`; `returned N accounts`; errored/sites ≤ 0.5; ndjson parses; record count == N |
| holehe | email | `holehe --no-color --no-clear --no-password-recovery -T 15 -- EMAIL` | proxy, or `UNMASK_HOLEHE_DIRECT=true` | registration `"EMAIL @ site"` · registered_on · B · .7 | – | 300 | `N websites checked in`; classified ≥ min(N,20); rate-limited/N ≤ 0.5. Lines `[+]` used `[-]` not `[x]` rate-limited |
| h8mail | email | `h8mail -c cfg.ini -j report.json -t EMAIL` (cfg `[h8mail]` k=v) | `UNMASK_H8MAIL_KEYS` (≥1 known key) | breach `"Name (TAG)"` · exposed_in · rel by tag (HIBP3 B, HUNTER/EMAILREP C, else D) · .7; co-leaked username/name/ip · breach_associated · D · .5 | – | 300 | "Session Recap" in stdout; report.json has `targets[].target == EMAIL` |
| theharvester | domain | `theHarvester -d DOM -b SOURCES -f report` | – (sources `crtsh,hackertarget,rapiddns,otx,certspotter,urlscan`) | email · email_at_domain · C · .5; hostname · subdomain · C · .6; ip · resolves_to · C · .5 | – | 600 | report.json exists; `[*] Searching X` lines; exceptions < number of sources |
| amass | domain | `amass enum -passive -nocolor -timeout 8 -dir amass-data -json names.json -log amass.log -d DOM` | – | hostname · subdomain · C · .6 (+addresses, sources); apex excluded | – | 660 | "The enumeration has finished"; `Querying X for … subdomains` in log; failed sources/queried ≤ 0.5 |
| spiderfoot | domain, ip | `spiderfoot -s T -o json -max-threads 3 (-m MODS \| -u passive)` | – | per type map below · spiderfoot_link | – | 2700 | `Scan completed with status FINISHED`; JSON list between first `[` and last `]` |

SpiderFoot map: Internet Name→hostname C .6; Affiliate Internet Name→hostname D .3; Domain Name→domain C .6;
Email Address→email C .5; IP/IPv6→ip C .5; Human Name→name D .3; Username→username D .4;
Phone Number→phone C .4; Account on External Site / Social Media Presence→account C .4; Hacked Email→breach C .5.
Drop empty or >512-char data and values equal to the target; dedupe (type,value).

h8mail details: known keys `hibp snusbase_token leak-lookup_pub leak-lookup_priv dehashed_email dehashed_key intelx_key
breachdirectory_user breachdirectory_pass emailrep hunterio weleakinfo_priv weleakinfo_pub`. Fields matching
`PASS|HASH|MD5|SALT` are **never stored** — only `{kind, fingerprint: digest("credential", v)[:12]}`.

Free HTTP lookups:

| Tool | In | Endpoint | Emits | Notes / proof |
|---|---|---|---|---|
| crtsh | domain | `https://crt.sh/?q=%.DOM&output=json` (120 s) | hostname · subdomain · B · .6 (+cert dates, issuers) | must be list of dicts; strip `*.`, keep under DOM, drop apex |
| duckduckgo | username,email,name,domain,phone | `api.duckduckgo.com/?q=V&format=json&no_html=1&skip_disambig=1&no_redirect=1` | web_mention · mentioned_on · AbstractURL C / related D · .25 | must have Heading, RelatedTopics, AbstractURL |
| github | username, email | `/users/{u}`, `/users/{u}/social_accounts`; email → `/search/commits?q=author-email:E` (404/422 = none) → ≤3 authors | account B .55 (email path: committed_as .8); linked socials C .6; email has_email B .7 | optional `UNMASK_GITHUB_TOKEN`; record needs `login` |
| gitlab | username | `gitlab.com/api/v4/users?username=U` → `/users/{id}` | account B .55; linked C .6; email B .7 | list required |
| keybase | username | `keybase.io/_/api/1.0/user/lookup.json?usernames=U&fields=basics,profile,proofs_summary` | account B .55; proven accounts B .75 verified; dns/web proofs → domain controls_domain B .75 | needs `status` |
| hackernews | username | `hacker-news.firebaseio.com/v0/user/U.json` | account B .55 (bio, karma); email has_email C .65 | links read from raw `about` before tag stripping |
| gravatar | email | `en.gravatar.com/{md5(lower(email))}.json` | account has_profile B .85; linked C .6; preferredUsername → username uses_handle B .75 | 404 = none |
| leakcheck | email, username | `leakcheck.io/api/public?check=V` | breach exposed_in C .6 (email) / .4 (username) | `success=false` without "not found" = error |
| wayback | domain | CDX `web.archive.org/cdx/search/cdx?url=DOM/*&output=json&fl=timestamp,original,statuscode&filter=statuscode:200&collapse=urlkey&limit=5000` (90 s) | web_mention archived_page B .35 | keep paths `/(about\|team\|people\|staff\|contact\|leadership\|who-we-are\|company\|founders?)…`, ≤30, newest per path |
| rdap | domain | `rdap.org/domain/DOM` | enrich domain (registrar, dates, NS, registrant); name/email registered_by B .6/.65 | drop names/emails matching `redacted\|privacy\|withheld\|proxy\|not disclosed` |

Web search (`websearch`, in: username,email,name,domain,phone; page check yes; 180 s):
- Provider = `UNMASK_SEARCH_PROVIDER` or first keyed of serper → serpapi → google → brave.
- Queries (≤ `UNMASK_SEARCH_MAX_QUERIES=8`, ≤4 concurrent, `UNMASK_SEARCH_RESULTS=10` each): always `"V"` and `"V" "tag"` (≤2 tags), plus
  - username: `site:` social (linkedin,x,twitter,instagram,facebook,tiktok), dev (github,gitlab,stackoverflow,reddit,medium,dev.to), `inurl:V`, `(filetype:pdf OR doc OR docx)`
  - name: `site:linkedin.com/in`, social, `(resume OR cv OR "about me" OR portfolio)`, documents, all-tags query
  - email: `"local" -"V"` (local ≥5 chars), paste/code sites (pastebin, github, gitlab, gist), documents
  - domain (replaces list): `site:V`, `"V" -site:V`, `"@V"`, tags
  - phone: + digits-only query
- Merge hits by normalised URL (lower host, drop fragment and `utm_*|fbclid|gclid|ref|ref_src`, strip `/`); keep best rank, longest snippet.
- Emits: web_mention · mentioned_on · D · `min(0.4, 0.25 + 0.05·(queries_hit−1))`; account (recognised profile whose handle relates to the target) · has_account · C · .4; other emails in snippets · mentioned_with · D · .3.
- All queries failing = error; partial failures tolerated.

| Provider | Request | Must contain |
|---|---|---|
| Serper | POST `google.serper.dev/search` `{q,num}`, `X-API-KEY` | `searchParameters` |
| SerpAPI | GET `serpapi.com/search.json?engine=google&q&num&api_key` | `search_metadata` |
| Google CSE | GET `googleapis.com/customsearch/v1?key&cx&q&num≤10` | `kind=customsearch#search` |
| Brave | GET `api.search.brave.com/res/v1/web/search?q&count≤20`, `X-Subscription-Token` | `type=search` |

Keyed APIs (unconfigured → skipped with "needs an API key"):

| Tool | In | Endpoint | Key env | Emits |
|---|---|---|---|---|
| hibp | email | `haveibeenpwned.com/api/v3/breachedaccount/E?truncateResponse=false` (`hibp-api-key`) | `UNMASK_HIBP_KEY` | breach exposed_in, A if IsVerified else B, .75 |
| hunter | domain | `api.hunter.io/v2/domain-search?domain&limit=50&api_key` | `UNMASK_HUNTER_KEY` | email email_at_domain C .45 (+name, position, sources) |
| emailrep | email | `emailrep.io/E` (`Key`) | `UNMASK_EMAILREP_KEY` | enrich reputation; registration per profile C .6 |
| shodan | ip | `api.shodan.io/shodan/host/IP?key&minify=true` | `UNMASK_SHODAN_KEY` | enrich ports/org/asn; hostname resolves_to B .6 (≤20) |
| ipinfo | ip | `ipinfo.io/IP/json[?token]` | `UNMASK_IPINFO_TOKEN` (optional; always runs) | enrich geo/org; hostname reverse_dns B .6 |
| virustotal | domain | `/api/v3/domains/D/subdomains?limit=40`, `/resolutions?limit=20` (`x-apikey`) | `UNMASK_VIRUSTOTAL_KEY` | hostname subdomain B .6; ip resolved_to B .5 |
| securitytrails | domain | `api.securitytrails.com/v1/domain/D/subdomains?children_only=false` (`APIKEY`) | `UNMASK_SECURITYTRAILS_KEY` | hostname subdomain B .6 (≤200) |
| numverify | phone | `http://apilayer.net/api/validate?access_key&number=DIGITS` | `UNMASK_NUMVERIFY_KEY` | enrich valid/country/carrier/line_type |

### 4.5 Health checks

| Tool | Target | Pass if |
|---|---|---|
| sherlock | `torvalds` on GitHub+GitLab | ≥1 of them found |
| maigret | `torvalds`, site GitHub | a github.com hit |
| holehe / h8mail | `unmask-health@example.com` / `test@example.com` | run completes (structure only); h8mail also no source errors |
| theharvester / crtsh / amass | `example.com` | ≥1 hostname / ≥1 candidate |
| spiderfoot | `example.com`, module `sfp_dnsresolve` | run completes |
| websearch / duckduckgo | "OWASP Amass" / "OWASP" | owasp or github host / ≥1 result |
| github / gitlab / keybase / hackernews | `torvalds` / `sytses` / `chris` / `pg` | name == "Linus Torvalds" / ≥1 candidate |
| gravatar, leakcheck, wayback | – | API answered |
| rdap | `example.com` | registration date present |
| hibp / emailrep / ipinfo / numverify / virustotal | test account / `bill@microsoft.com` / `8.8.8.8` (org has Google) / `14158586273` (valid) / `example.com` | as noted |
| hunter / shodan / securitytrails | account endpoint (`/v2/account`, `/api-info`, `/v1/ping`) | non-empty answer |

### 4.6 Installed versions (pin them)
sherlock-project 0.16.2 · maigret 0.6.6 · holehe 1.61 · h8mail 2.5.6 · theHarvester git tag 4.8.0 (+`pycares<5`) ·
SpiderFoot commit `0f815a203afebf05c98b605dba5cf0475a0ee5fd` · Amass v3.23.3 static zip, sha256
amd64 `2b5afb8a567d9703dfb416099fb0452e2b4b4da5170f0b23cd3b812df2e9319c`, arm64
`b67dfdf5659268bb48626ef39bf9c2c74c0b5d34d21c232a17e07ba200be11b5`. One venv per tool under
`/opt/tools/<name>`, entry points symlinked into `/opt/tools/bin`.

Focused site lists: ~120 high-signal sites each for Sherlock and Maigret (names must match each tool's own
site names); `UNMASK_USERNAME_SITES=all` disables them (Maigret then uses `--top-sites 200`).

---

## 5. Execution

Planning: one job per (target × tool whose `input_types` contains the target type), skipping tools that are
disabled, circuit-open, unconfigured, excluded by the case, or (quick depth) slow. Zero jobs → note
`_none: "No enabled tool accepts these target types yet"`.

Per job:
1. Take a tool slot: `max_concurrent=3`, lease = timeout + 120 s, hold `delay_ms=500` after finishing.
2. `run()` → `parse()`; if `verify_accounts`: page-check (§6), then one hop of linked accounts, page-checked too.
3. Persist under a per-case lock; upsert by (case, type, digest) including merged-away members
   (`prior = max`, `rel = min letter`, page check is sticky: a later failed check never overwrites a verified preview/reason);
   add an observation row; add `relation_type` from the parent (target seed or pivot entity).
4. Quick rescore (pass 1 only) so results show while the run continues.
5. Outcome: success resets `consecutive_failures`; AdapterError/unexpected error increments it; InvalidTarget doesn't count.

All jobs of a run execute concurrently (results appear tool by tool via step 4). After all jobs:
full correlation (pass 1 + 2) → notify → pivots.

Run status: failed tools and none completed → `failed`; any failure or skipped job → `partial`; else `completed`.
Run notes in `failure_details`: `_skipped _none _cancelled _interrupted _crashed _correlation _correlation_error _pivots _pivots_error _verification{tool:{counts,reasons(top5),sources{fetched,cached,reused}}}`.
Cancel: only queued/running; mark `cancelled`, note `stopped by X after d of n tool runs`, keep stored results, kill tools.
Starting a scan while one is active returns the active run. Leftover queued/running runs at startup → `failed` + `_interrupted`.

Circuit breaker: `CIRCUIT_BREAKER_THRESHOLD = 3` consecutive failures → `enabled=false, circuit_open=true`, alert.
Recovery only via a passing health check (re-enables). Scheduler re-checks breaker-tripped tools every
`UNMASK_HEALTHCHECK_HOURS=24`; tools a human disabled are left alone.
Tool status: `off` (not configured) > `down` (circuit open) > `off` (disabled) > `degraded` (last check failed or failures>0) > `ok`.

Templates:

| Template | Targets | Depth | Tools | Watch |
|---|---|---|---|---|
| due_diligence | name, email, username | deep | default | – |
| username_sweep | username | quick | sherlock, maigret, websearch, duckduckgo | – |
| email_exposure | email | quick | holehe, h8mail, websearch, duckduckgo | – |
| domain_footprint | domain | deep | crtsh, theharvester, amass, spiderfoot, websearch | weekly |
| impersonation | name, username | quick | default | "daily" (unsupported → weekly) |

Seeds: every target is stored as an entity `source_tool=analyst, p=1.0, rel=A, is_seed=true`.

---

## 6. Page verification (account hits from sherlock, maigret, websearch)

Fetch: desktop Chrome UA, redirects ≤5, timeout `UNMASK_VERIFY_TIMEOUT=8` s, read ≤200 KB, classify the first 60 KB,
concurrency 12 overall and `PER_HOST=2` across all jobs, ≤`UNMASK_VERIFY_MAX=250` per job (rest: "not checked (verification limit reached)").
One retry for timeout/connect/protocol errors and HTTP 429/502/503/504 (Retry-After ≤5 s, else 0.5–1.5 s jitter); never for login/bot/not-found pages.
Verdict cache per process: key (url, folded username), 512 entries, TTL 30 min, concurrent requests share one fetch; failed loads not cached.
Reuse: a case account verified within `UNMASK_REVERIFY_DAYS=7` is not refetched. Redirect loop → rejected; other HTTP error → unverified.

`classify(url, user, status, final_url, page)` — `fold(x)` = casefold, remove `[\s._\-]`; title_text = og/twitter title + `<title>`:

| # | Condition | Verdict |
|---|---|---|
| 1 | status 404/410 | **rejected** "page not found" |
| 2 | status 401/403/429/503 or BOT_WALL in title | unverified "blocked by bot protection" |
| 3 | status ≥ 400 | unverified "site answered HTTP n" |
| 4 | redirected and fold(user) ∉ fold(final path): LOGIN_PATH → **rejected** "redirects to a login page"; path `/` or other host → **rejected** "redirects away" | |
| 5 | NOT_FOUND in title | **rejected** "says the profile does not exist" |
| 6 | fold(user) in fold(title \| page_title \| description \| profile:username \| canonical) | **verified** "profile page names the username in its <field>" + links, emails, matched_in, excerpt |
| 7 | LOGIN in title | unverified "login wall" |
| 8 | BOT_WALL in first 3000 chars of visible text | unverified |
| 9 | NOT_FOUND in first 4000 chars of visible text | **rejected** |
| 10 | fold(user) in visible text | unverified "appears on the page but not as its subject" (+excerpt, matched_in=[body]) |
| 11 | else | unverified "does not mention the username" |

Rejected → dropped (counted). Others get `verification`, `verification_reason`, `preview`.

Regexes (case-insensitive):
- BOT_WALL: `just a moment|attention required|cf-browser-verification|cf-chl-|captcha|are you a robot|are you a human|verify you are human|access denied|request unsuccessful|ddos-guard|checking your browser|unusual traffic|px-block`
- NOT_FOUND: `page not found|profile not found|user not found|account not found|not be found|(?:doesn.t|does not|no longer) exist|isn.t available|is not available|no longer available|nothing (?:was )?found|couldn.t find|could not find|can.t find|cannot find|account (?:has been )?(?:suspended|deactivated|terminated)|\b404\b|this user has been`
- LOGIN: `\b(?:log ?in|sign ?in|sign ?up|create an account|join)\b`
- LOGIN_PATH: `/(?:login|signin|sign-in|log-in|signup|sign-up|join|register|auth|accounts/login)\b`

Preview (each ≤500 chars): title = og:title → twitter:title → `<title>`; page_title; description = og:description → description → twitter:description;
image (URL only, never fetched); username = `profile:username`; canonical; plus status, checked_at.
Visible text = drop `<nav>`/`<footer>` blocks, scripts/styles and tags, unescape, collapse spaces.
Excerpt = 280 chars around the first match of the term's letters joined by `[\s._\-]?`, starting 1/3 before the match, trimmed to words with `…`.

Links on a verified page (≤20, profiles first) + `mailto:` emails (≤5, lowercased): only off-site `http(s)` links outside nav/footer;
skip boilerplate hosts (google, apple, microsoft, mozilla, cloudflare, gstatic, w3, schema, creativecommons, gravatar, wikipedia,
archive.org, cookie/consent vendors, app stores, bit.ly); skip non-profile pages on known sites; skip the site's own accounts
(handle contains the page's or link's brand, brand ≥4 chars) unless the handle relates to the username.
Base domain = last 3 labels if second-to-last ≤3 chars (co.uk) else last 2; brand = its first label.

Linked accounts (one hop): each recognised profile link on a verified page → account · has_account · C · .6,
fc `{exists .7, same_person .6}`, `linked_from`, explanation "the X profile links to it"; page-checked like the rest.

Recognised profile sites (`match_profile`): GitHub, GitLab, X/Twitter, Instagram, Facebook, LinkedIn `/in/`, TikTok `/@`,
Reddit `/u|user/`, Medium `/@`, YouTube `/@`, Telegram, Keybase, Twitch, Pinterest, Stack Overflow `/users/N/h`,
Hacker News `user?id=`; handle `[A-Za-z0-9][A-Za-z0-9._\-]{0,62}`; per-site stop-words for non-profile paths.

`handle_relates_to(h, target)` (target email → local part; both squashed to `[a-z0-9]`, `len(h)≥2`): true if
`h==t`, or `t⊂h` with `len(t)≥4`, or `h⊂t` with `len(h)≥5`, or SequenceMatcher ≥0.8, or ≥2 name parts (≥2 chars) in h,
or 1 part (≥3 chars) in h and h starts/ends with another part's initial.

---

## 7. Normalisation and correlation

Canonical forms:

| Type | Canonical |
|---|---|
| any | `fold` = NFKD, drop combining marks, casefold, strip |
| email | fold; gmail/googlemail: cut `+tag`, remove dots, domain gmail.com |
| account (URL) | host lower, strip `www.` then `m.`; path rstrip `/` lower; keep query; no scheme |
| domain / hostname | fold, strip trailing `.`; domain also strips `www.` |
| name | fold, `_`/punctuation → space, collapse, **sort tokens** |
| phone | digits only; strip leading 0s unless raw starts with `+` |
| ip | `ipaddress` canonical form |
| handle(v) | fold minus `[._\-]`; email_handle = local part, cut `+`, minus `[._\-]` |

`initials_compatible(a,b)`: every token of the shorter name consumes a distinct token of the longer one, equal or as a 1-letter initial.

Pass 1 (rules, deterministic):

| Step | Rule | Result |
|---|---|---|
| a. auto-merge | same type and same canonical value, unless `not_same` | merge (only automatic merge) |
| b. names | `ratio(canon a, canon b) ≥ 85`, or initials compatible and ≥ 60 | `possible_same`, conf = ratio/100 |
| c. usernames | handle equal → conf .9; else `ratio(fold) ≥ 90` → ratio/100 | `possible_same` |
| d1 | email ↔ username: email_handle == handle (non-empty) | `shares_handle` .7 |
| d2 | email ↔ domain: email domain == canonical domain | `email_at_domain` .8 |
| d3 | account ↔ name: a profile name has ratio ≥ 90 and compatible initials | `profile_name_match` ratio/100 |
| d4 | verified account's links ↔ account/web_mention (same url key), domain (host == or ends with .dom), email (canonical) | `profile_links_to` .9 |

Pairs already linked by `not_same`, `same_as` or `possible_same` are "blocked" for suggestions; existing links are not duplicated.
Profile names = `profile.fullname|name`, plus (verified only) a display name parsed from the page title: strip trailing
`· | / – — : -` segments, `(…)`, `@handle` up to 3 times; for "handle (Name)" take the bracket; accept 2–5 words, ≥80% letters,
not starting with profile/user/posts/about/account/member/overview/page, not the handle again.

Pass 2 (semantic, end of run only): names and usernames, same type, not blocked and not already corroborated;
`all-MiniLM-L6-v2` normalised embeddings, cosine ≥ `UNMASK_EMBEDDING_THRESHOLD=0.8` → `possible_same` (conf = similarity).
Run the model in a short-lived child process (≈300 MB, exits after each call, 120 s timeout); missing model/library →
report "skipped (reason)", never substitute.

Merge: winner = seed > confirmed > oldest; members re-pointed; attributes pooled (winner wins, `profile`/`fields` dicts merged,
score explanation dropped); confirmed = OR; first_seen = min; last_verified = max; rel = best letter;
`possible_same` → `same_as` (conf 1). Split: clear `merged_into`, delete same_as/possible_same, add `not_same` (analyst).
Reject suggestion: `possible_same` → `not_same`. Analyst `same_as`/`not_same` are never overridden.

---

## 8. Scoring

Inputs per finding: prior (`fc.prior`, set from the adapter's p, max over sightings), reliability letter, number of distinct
tools (incl. merged members, excl. analyst; ≥1), corroborating relation **types** (distinct), page check, username rarity
(accounts with a username and not linked), site factor (accounts), tag match (non-seeds).

```
REL = {A:1.0, B:0.85, C:0.7, D:0.5, E:0.3, F:0.4}         (unknown → 0.4)
if seed or confirmed: score = 1.0 (model score still recorded)
w     = REL[rel]
base  = clamp01(prior) · (0.6 + 0.4·w)
if rarity < 1:               base ·= 0.5 + 0.5·rarity
if site_factor ≠ 1:          base  = min(0.95, base · site_factor)
if page == unverified:       base ·= 0.55
doubt = 1 − base
if page == verified:         doubt ·= 1 − 0.35
repeat (tools − 1):          doubt ·= 1 − 0.2·w
for each of ≤3 corroborations: doubt ·= 1 − 0.25
if tag_match:                doubt ·= 1 − 0.3·tag_match
score = round(clamp(1 − doubt, 0, 0.99), 4)
```

Every step appends a plain-English line to the score explanation (e.g. "prior 0.40 weighted by reliability C → 0.35",
"profile page checked: it exists and names the username", "seen by 2 independent tools", "corroborated: shares handle").

Tag match: tags with ≥3 chars; hit if substring of the casefolded attribute text (minus internal keys) or
`partial_ratio ≥ 90`; score = hits/usable; no usable tags → none.

Username rarity (`h` = casefold minus `[._\-\s]`):

| Condition | Rarity |
|---|---|
| empty | 1.0 |
| ≤3 chars | 0.15 |
| in common-words/first-names list (~300) | 0.25 |
| common word + ≤2 trailing digits | 0.35 |
| all digits | 0.30 |
| else | clamp(0.35 + 0.05·len, 0.5, 1.0) |

Site factor (learned from the analyst's own decisions across cases, per site host): confirmed/dismissed non-seed accounts;
`precision = (confirmed + 2) / (decisions + 4)` (Beta(2,2)); fewer than 3 decisions → 1.0; else `0.6 + 0.8·precision` (0.6–1.4).

Bands: **Likely ≥ 0.70**, **Possible ≥ 0.45**, Unlikely below. Weak = < 0.30.
Default view hides, in order: dismissed; (seed/confirmed always shown); web_mention; unverified account; score < 0.30.
Review queue = not merged, not seed, not confirmed, not dismissed, not web_mention, not hidden; sorted by score desc, then first seen.

---

## 9. Evidence lines (what `unmask show` prints)

Subject handles = username targets + email local parts; subject names = name targets; tags = all target tags.

| Kind | Line | Rule |
|---|---|---|
| ✓ | Profile page checked — reason · checked DATE | verified account |
| ✗ | Profile page couldn't be confirmed — reason | unverified account |
| · | Profile page not checked | account, no check |
| ✓ | Same username as the subject | handle equal |
| ✓ | Username resembles the subject's | `handle_relates_to` |
| ✗ | Different username | neither, and not linked from a profile |
| ✗ | Common username: a match means little | account, not linked, rarity < 0.5 |
| ✗ | Looks like the site's own account | handle contains the site's brand |
| ✓ | Display name matches the subject ('A' ≈ 'B' (91%)) | best `token_sort_ratio(canon names) ≥ 85` |
| · | Display name is similar | initials compatible and ≥ 60 |
| ✗ | The page names someone else | otherwise (when both names exist) |
| ✓ | Mentions the case context: tag, tag | tag found in name/bio/location/excerpt/title (substring or partial_ratio ≥ 90) |
| · | None of the case tags appear on the page | verified account, none found |
| ✓ | Linked from another profile | `linked_from` |
| ✓ | Links to what you already know: … | a page link/email equals a target or confirmed finding (≤3 named) |
| ✓ | Corroborated: <relation explanation> | each corroborating relation, deduped; skip name-match if the display-name line exists |
| · | May be the same as another finding | `possible_same` |
| ✓ | Found by N tools | ≥2 non-analyst tools |

Summary: `"N for · M against"` or "No evidence either way". Card also prints name, @handle, site, location, bio,
the page excerpt (matching words highlighted), and link chips tagged `target` / `confirmed` / `in case`.

---

## 10. Pivots

Trigger: finding not merged, not dismissed, type matches, `score > min` (strict); processed by score desc, then first seen.

| From | Min | Tools | Input |
|---|---|---|---|
| username | 0.6 | holehe | guessed `u@{gmail.com,outlook.com,yahoo.com,proton.me}` (`UNMASK_PIVOT_EMAIL_PROVIDERS`), local part `^[a-z0-9][a-z0-9._\-]{0,63}$` |
| username | 0.6 | maigret, github, keybase, gitlab | same value |
| email | 0.6 | h8mail, gravatar, github, hibp, leakcheck, emailrep | same value |
| email | 0.6 | theharvester | the email's domain unless shared |
| domain | 0.0 | amass, crtsh, spiderfoot, rdap, wayback, hunter, virustotal, securitytrails | canonical domain unless shared |
| ip | 0.5 | ipinfo, shodan | same value |

SHARED_DOMAINS (never pivoted into): gmail, googlemail, outlook, hotmail, live, msn, yahoo, ymail, icloud, me, mac, aol,
proton.me, protonmail, pm.me, gmx.com/.de, mail.com, yandex.com/.ru, zoho, qq, 163, github, gitlab, google, facebook,
twitter, x, linkedin, instagram, reddit, medium, wordpress, blogspot.

Dedupe key `(tool, input type, canonical input)` against inputs already run (non-pivot runs that included the tool + started pivots);
each (finding, tool) logged once. Skip reasons (logged): tool unavailable/unconfigured/excluded → depth > `UNMASK_PIVOT_MAX_DEPTH=2`
(depth = source run depth + 1) → started ≥ `UNMASK_PIVOT_BUDGET=20` this evaluation. Started rows become one `pivot_chain` run.
Case switch `auto_pivot` (default on). A guessed email with any hits → email finding · guessed_email · C · .45,
fc `{registered .8, same_person .45}`.

---

## 11. Watch, retention, scheduler (`unmask tick` from cron/systemd timer)

- Watch: `weekly`=7 d, `monthly`=30 d; next = now + period ± uniform jitter `min(period·10%, 12 h)`; per tick start ≤ `UNMASK_WATCH_MAX_PER_TICK=3`
  random due cases (others wait), skip cases with an active run; always advance `next_run_at`. Watch runs only notify when something new was found.
- Retention: deadline = max(created, latest run) + `retention_days` (default 90, 1–3650; samples 30); `permanently_active` never purges;
  warn when < 7 days left; viewing never resets the clock; skip while a run is active; audit `retention_purge`.
- Health checks: every `UNMASK_HEALTHCHECK_HOURS=24` (0 = off) for configured tools, including breaker-tripped ones.
- Interval for a daemon mode: `UNMASK_SCHEDULER_INTERVAL=300` s; a lock ensures one ticker.

---

## 12. Outputs

Scopes: `visible` (no dismissed), `confirmed` (confirmed + targets), `all`; merged-away members always excluded;
order targets → confirmed → score desc; sources = tools across the finding and its merged members.
Decision values: `target confirmed ruled out undecided`.

CSV columns: `value,type,site,url,decision,not_them_reason,confidence,source_reliability,page_check,sources,merged_duplicates,first_seen,last_seen,id`
(confidence `.2f`, sources `; `-joined, UTF-8 BOM). Cells starting with `= + - @ \t \r` are prefixed with `'`.

JSON: `{format:"unmask-case-export", version:1, exported_at, scope,
case:{id,name,created_at,authorization_note,lawful_basis_confirmed_at,analyst_assessment,targets[{type,value,context_tags}]},
findings[{id,type,value,decision,not_them_reason,confidence(4dp),source_reliability,page_check,sources,merged_duplicates,first_seen,last_seen,attributes(no _keys)}],
links[ both ends exported ], snapshots[{finding,url,final_url,captured_at,status_code,sha256,bytes}]}`.

STIX 2.1:

| Finding | STIX |
|---|---|
| email | `email-addr` |
| domain, hostname | `domain-name` |
| ip | `ipv4-addr` / `ipv6-addr` |
| username | `user-account{account_login}` |
| account | `user-account{account_login, account_type=site, x_unmask_site, x_unmask_profile_url}` |
| web_mention, image, http(s) values | `url` |
| name, phone | `identity` (individual; confidence×100; phone → contact_information) |

Observable ids: uuid5 (OASIS namespace `00abedb4-aa42-466c-9c01-fed23315a9b7`) of canonical JSON; other ids uuid5(case_id, key).
Custom props `x_unmask_confidence/decision/source_reliability/sources`. Relations → `relationship` `related-to` (+`x_unmask_relation`).
`grouping` (context unspecified) and the assessment `note` marked TLP:AMBER `marking-definition--f88d31f6-486f-44da-b317-01333bde0b82`;
empty export → "No findings" note; bundle id uuid4; timestamps `YYYY-MM-DDTHH:MM:SS.mmmZ`.

Markdown report: requires an analyst assessment ≥ 40 chars (≤ 20000); includes authorization note and lawful-basis time.

Snapshot: GET through the SSRF guard (§2) and the `verify` proxy; store url, final_url, status, content_type[:200],
sha256(raw), size, truncated, `<title>`[:300], body (base64, encrypted). `snapshot verify` re-hashes the body.

Graph (`--json` / `--dot`): nodes = active findings (merged collapsed, dismissed removed) with
`label, value, type, site, confidence, strength(target|confirmed|likely|possible|unlikely|unchecked), verification, seed, confirmed, pivot, merged, centrality`;
edges deduped per (a,b,type), `same_as`/`not_same` omitted, with `kind` (strong = corroborating, suggested = possible_same, link = other),
`why` (explanation), `confidence`. Centrality = undirected PageRank (d=0.85, 40 iterations) normalised to max 1.
>400 nodes → keep targets/confirmed/likely/possible first, report `hidden` count (`--all` disables).
DOT mapping: shape by type (username ellipse, email/account box, name diamond, domain hexagon, ip pentagon, breach octagon,
web_mention triangle), penwidth by strength, `style=dashed` for possible, `style=dotted` + gray for weak/unchecked,
peripheries=2 for targets, strong edges bold with arrows, suggested edges dashed orange.

---

## 13. Configuration

Settings come from env (`.env` honoured); a stored secret with the same name overrides its env var.

| Group | Variables (default) |
|---|---|
| Keys | `UNMASK_DATA_KEYS` (Fernet, comma list), `UNMASK_INDEX_KEY` — both required |
| Execution | `UNMASK_TOOLS_BIN`, `UNMASK_TOOL_TIMEOUT=300`, `UNMASK_TOOL_PROCS=3`, `UNMASK_SCAN_JOB_TIMEOUT=7200` |
| Tools | `UNMASK_USERNAME_SITES=focused\|all`, `UNMASK_MAIGRET_TOP_SITES=200`, `UNMASK_H8MAIL_KEYS`, `UNMASK_HARVESTER_SOURCES=crtsh,hackertarget,rapiddns,otx,certspotter,urlscan`, `UNMASK_SPIDERFOOT_USE_CASE=passive`, `UNMASK_CRTSH_URL=https://crt.sh/` |
| Search | `UNMASK_SEARCH_PROVIDER`, `UNMASK_SERPER_KEY`, `UNMASK_SERPAPI_KEY`, `UNMASK_GOOGLE_API_KEY`+`UNMASK_GOOGLE_CX`, `UNMASK_BRAVE_API_KEY`, `UNMASK_SEARCH_MAX_QUERIES=8`, `UNMASK_SEARCH_RESULTS=10` |
| API keys | `UNMASK_GITHUB_TOKEN` (optional), `UNMASK_HIBP_KEY`, `UNMASK_HUNTER_KEY`, `UNMASK_EMAILREP_KEY`, `UNMASK_SHODAN_KEY`, `UNMASK_IPINFO_TOKEN` (optional), `UNMASK_VIRUSTOTAL_KEY`, `UNMASK_SECURITYTRAILS_KEY`, `UNMASK_NUMVERIFY_KEY` |
| Proxy | `UNMASK_PROXY_URL`, `UNMASK_PROXY_TOOLS=holehe,sherlock,maigret,verify` (`all` ok), `UNMASK_HOLEHE_DIRECT=false` — proxy reaches subprocesses only via env (`HTTP(S)_PROXY`), never argv; mask password when printing |
| Verify | `UNMASK_VERIFY_ACCOUNTS=true`, `UNMASK_VERIFY_TIMEOUT=8`, `UNMASK_VERIFY_CONCURRENCY=12`, `UNMASK_VERIFY_MAX=250`, `UNMASK_REVERIFY_DAYS=7` |
| Pivots | `UNMASK_PIVOT_MAX_DEPTH=2`, `UNMASK_PIVOT_BUDGET=20`, `UNMASK_PIVOT_EMAIL_PROVIDERS=gmail.com,outlook.com,yahoo.com,proton.me` |
| Scheduler | `UNMASK_SCHEDULER_INTERVAL=300`, `UNMASK_WATCH_MAX_PER_TICK=3`, `UNMASK_HEALTHCHECK_HOURS=24`, `UNMASK_ALERT_WEBHOOK_URL` |
| Embeddings | `UNMASK_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2` (empty = off), `UNMASK_EMBEDDING_CACHE`, `UNMASK_EMBEDDING_THRESHOLD=0.8` |
| Legal | `UNMASK_OPERATOR_NAME`, `UNMASK_LEGAL_CONTACT`, `UNMASK_GOVERNING_LAW=Singapore` |

Which key unlocks what: serper/serpapi/google/brave → websearch; github → github (higher rate limit); hunter, emailrep, hibp,
shodan, virustotal, securitytrails, numverify → same-named tool; h8mail keys → h8mail; ipinfo → better ipinfo; proxy → holehe (required), sherlock, maigret, page checks.
Print keys masked: `••••••` + last 4 chars when longer than 8.

---

## 14. Evaluation harness (`unmask eval`)

Input JSON: `{authorization: "non-empty", identities: [{username, tags?, expected: [profile URLs, non-empty]}]}`.
Per tool × identity: *reported* = account keys the tool returns; *shown* = after page checks + verified linked accounts.
Key = site host + lowercased path (no trailing `/`) + lowercased query. Metrics (3 dp): precision/recall for reported and shown,
`missed` = expected − shown, `false_positives` = shown − expected, seconds. Totals pooled per tool. Expected lists are assumed
complete (an unlisted real account counts as a false positive). Default tools: sherlock, maigret, websearch.

Calibration report (from decisions): per band, confirmed / decided using the model score; per tool and per site confirm/dismiss rates;
dismiss-reason counts.

---

## 15. Suggested CLI architecture

```
unmask/
  cli.py          argparse/typer subcommands, output formatting, exit codes
  store.py        SQLite (WAL) schema of §3; one write transaction per job; advisory lock = BEGIN IMMEDIATE
  crypto.py       MultiFernet + HMAC blind index (§3)
  config.py       env + stored secrets overlay (§13)
  adapters/       base.py (contract, sandbox, validators), http.py, one module per tool (§4)
  throttle.py     per-tool slots + global process cap (§5)
  verify.py       page checks, cache, links (§6)
  correlate.py    normalise, pass 1/2, merge/split (§7)
  score.py        formula, rarity, site factor (§8)
  signals.py      evidence lines (§9)
  pivots.py       rules + dedupe (§10)
  scheduler.py    tick: watch, purge, health (§11)
  export/         csv, json, stix, md, graph(dot/json) (§12)
  embed_worker.py child process for pass 2
```

Stack: Python 3.11, asyncio, httpx, rapidfuzz, cryptography; optional sentence-transformers (+CPU torch) only in the child process.
Drop from the web build: FastAPI, Jinja/htmx, RQ/Redis (use asyncio + SQLite; one process), users/sessions/share links/notifications
(keep an `--actor` name for the audit log). Keep: audit log, lawful-basis gate, encryption at rest.
Kali packaging: Debian package `unmask` depending on python3; post-install creates `/opt/unmask/tools/<tool>` venvs at the pinned
versions (§4.6) with checksums; config in `~/.config/unmask/env`; man page generated from `--help`.

Memory notes from production: keep torch out of the main process (child per call); cap concurrent tool processes (they are
50–500 MB each); return heap after big runs (`gc.collect()` + `malloc_trim(0)`, `MALLOC_ARENA_MAX=2`).

---

## 16. Gotchas found while extracting

- Relation names are inconsistent: VirusTotal `resolved_to`, Shodan/theHarvester `resolves_to`, IPinfo `reverse_dns` — normalise in the CLI.
- The `impersonation` template asks for daily watch, but only weekly/monthly exist (falls back to weekly).
- Jobs run all at once; "fast first" only means results are rescored and shown as each tool finishes.
- Reliability weight E (0.3) is lower than F (0.4) — deliberate or not, keep it or fix it consciously.
- ipinfo and the free lookups have no configured gate, so they always run.
- Holehe/h8mail health checks use reserved example addresses: they test output structure, not real detection.
- Target sites' robots.txt is not consulted; snapshot SSRF guard has a DNS-rebinding window (mitigated by the proxy).
- Score explanations count distinct corroborating relation *types*, not individual relations.
