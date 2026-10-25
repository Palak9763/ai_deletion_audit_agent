# Data Map — Ghost Data Still Exists

Phase 0 recon. Written 2026-10-24.

---

## 1. Structured Dataset Files (dataset/)

### 1.1 deletion_requests.csv & sample_deletion_requests.csv

| Field | Type | Notes |
|---|---|---|
| case_id | string | Primary key — case_NNN (e.g. case_01). 518 rows in full file, 32 in sample. |
| email | string | Email supplied with the request. May be current OR historical. |
| requested_at | ISO-8601 | When the request was submitted. |
| reported_status | enum | Claim from the deletion workflow: COMPLETE, PARTIALLY_COMPLETE, NOT_STARTED. NOT proof. |
| reported_at | ISO-8601 | When the workflow reported that status. |
| audit_at | ISO-8601 | Cutoff — only evidence captured <= this time is in scope. |
| request_text | free text | Multilingual free text. Must be evaluated to confirm deletion intent. |

User link: via email -> matched against user_identities.csv (current or historical email).
Identifiers exposed: email only at request time.

---

### 1.2 user_identities.csv

| Field | Notes |
|---|---|
| user_id | Stable internal key — user_NNN. Never changes. |
| name | Full name (direct identifier). |
| email | Current primary email (direct identifier). |
| phone | Current phone (direct identifier). |
| email_hash | SHA-256 of email (quasi-identifier). Changes when email changes. |
| updated_at | Snapshot time of this row. |

User link: user_id is the root identity key.
Identifiers exposed: user_id, name, email, phone, email_hash.

---

### 1.3 user_audit_log.csv

| Field | Notes |
|---|---|
| audit_id | Record key — audit_NNN. |
| user_id | Links to user_identities.csv. |
| event_time | When the field changed. |
| field_name | email, email_hash, or phone. |
| old_value | Previous identifier value. |
| new_value | Updated identifier value. |

Purpose: reconstruct historical identifiers (old emails, old email hashes, old phones) that may still appear in older evidence.
User link: user_id.
Identifiers exposed: user_id, historical email, email_hash, phone.

---

### 1.4 system_activity.csv

| Field | Notes |
|---|---|
| activity_id | Event key — activity_NNN. |
| event_time | ISO-8601 timestamp. |
| event_type | Enum — see below. |
| source_system | Originating service (e.g. deletion_worker, account_service). |
| target_system | Target service (e.g. search_service, analytics_platform). |
| resource_id | Affected resource (e.g. account_001, search_001, backup_001). |
| reported_result | SUCCESS, FAILED, PARTIAL. Claim only — must be verified against evidence. |
| details | Free-text description. |

Known event_type values: INDEX_RECORD, UPDATE_RECORD, DELETE_RECORD, ANONYMIZE_RECORD, REDACT_RECORD, RETAIN_RECORD, SYNC_RECORD, SEND_EMAIL, REFRESH_CACHE, CREATE_EXPORT, BACKUP_CREATE, RESTORE, BLOCK_RESTORE, DISABLE_CONNECTOR, ENABLE_CONNECTOR.

User link: via resource_id (matched to evidence record IDs) or via details text containing email/phone.
Identifiers exposed: resource IDs, system IDs. Some details fields contain email or phone directly.

---

### 1.5 deletion_rules.csv

| Field | Notes |
|---|---|
| rule_id | rule_NN. |
| data_category | See rules_map.md. |
| condition | Natural-language condition triggering the rule. |
| required_action | DELETE, REDACT, ANONYMIZE, or RETAIN. |

User link: n/a — this is policy, not evidence.

---

### 1.6 evidence_files.csv

| Field | Notes |
|---|---|
| file_id | evidence_NN (e.g. evidence_01). Used as evidence_id in steps_json. |
| file_path | Relative path under dataset/. |
| origin | Originating service name. |
| captured_at | ISO-8601. Only evidence <= audit_at may be cited for that case. |

User link: manifest does not identify the case/user — must be inferred from file contents.

---

## 2. Evidence Files (dataset/evidence/)

A single evidence file may contain data for multiple users — it is a global snapshot, not per-case.

---

### 2.1 evidence/records/ — JSON snapshot bundles

Format: JSON object with exported_at, source, snapshots array. Each snapshot has data_store, collection, captured_at, records array.

Key collections:

| data_store | collection | Resource ID prefix | Identifiers in record |
|---|---|---|---|
| account_service | customer_profiles | account_NNN | customer_reference (user_id), full_name, email, phone, account_status |
| identity_service | deleted_customer_references | tombstone_NNN | subject_reference (user_id), name, email, phone, email_hash, account_status |
| security_service | security_audit_events | audit_record_NNN | subject_reference (user_id), event_name, actor_type, integrity_seal |
| analytics_platform | customer_analytics_reports | analytics_NNN | user_id, email, phone, email_hash (all nullable post-anonymization) |
| support_platform | support_conversations | support_NNN | subject_reference (user_id), ticket_id, channel, message_text |
| integration_service | connector_configurations | data_flow_NNN | connector_name, destination, subject_selector (email or user_id), enabled (bool) |
| export_service | export_manifest/export_jobs | export_NNN | user_id, email, download link |
| backup_service | backup_catalog | backup_NNN | subject_reference (user_id), restore_allowed (bool) |
| search_service | customer_search_documents | search_NNN | display_name, email, customer_reference (user_id) |

User link: customer_reference, subject_reference, or user_id field matches user_identities.user_id. Email/phone also match directly.

---

### 2.2 evidence/databases/ — SQL snapshot files

Format: SQLite-compatible SQL dump with BEGIN TRANSACTION; CREATE TABLE; INSERT rows.
Two tables per file: customer_data_primary and customer_data_<type> (replica variant).
Each INSERT row has: resource_id, origin_system, collection_name, record_json, updated_at.
Comparing primary vs replica tables reveals REPLICATION DRIFT.

Database variants:

| Filename pattern | Replica type |
|---|---|
| read_replica_YYYYMMDD.sql | Read replica |
| regional_replicas_YYYYMMDD.sql | Regional replication |
| reporting_replica_YYYYMMDD.sql | Reporting replica |
| failover_replica_YYYYMMDD.sql | Failover replica |
| inventory_YYYYMMDD.sql | Data inventory scan |
| accounts_failover_replica_YYYYMMDD.sql | Account service failover |
| search_primary_YYYYMMDD.sql | Search index primary |

User link: record_json fields user_id, customer_reference, subject_reference, email, email_hash, phone.

---

### 2.3 evidence/logs/ — Plain-text service logs

Format: Structured key=value lines with timestamp, level, service, instance, pod, region, trace_id, event, resource_id, and identity lookup fields.

Key events:

| event | Meaning | Identity fields |
|---|---|---|
| profile_lookup_completed | Account found/absent (rows=0 -> absent) | lookup_key (email), resource_id |
| index_query_completed | Search index hit/miss | correlation_key (email), resource_id |
| analytics_identity_scan | Analytics PII found | matched_value (email), resource_id |
| message_pii_scan | Support message PII found | matched_value (email), resource_id |
| attachment_pii_scan | Support attachment PII found | matched_value (phone), resource_id |
| restore_policy_check_completed | Backup restore risk | subject_key, resource_id |
| connector_config_read_completed | Integration connector status | subject_key, resource_id |
| audit_record_read_completed | Security audit record | correlation_key (user_id), resource_id |

Log file categories:

| Pattern | Source | Content |
|---|---|---|
| service_events_*.log | central_observability_export | Multi-service event stream |
| structured_service_events_*.log | central_observability_export | Structured events |
| application_trace_*.log | central_observability_export | Application traces |
| cloud_runtime_export_*.log | central_observability_export | Cloud runtime events |
| operations_stream_*.log | central_observability_export | Operational events |
| syslog_archive_*.log | central_observability_export | Syslog archives |
| resource_lookup_trace_*.log | service_readback_logs | Resource lookup readbacks |
| search_index_diagnostic_*.log | search_index_service | Search diagnostics |
| notification_delivery_*.log | downstream_delivery_service | Email delivery events |
| support_replica.log | support_platform | Support replica events |

User link: lookup_key, subject_key, correlation_key, matched_value contain email/phone/user_id. resource_id matches system record IDs.

---

### 2.4 evidence/documents/ — PDF documents

Format: Binary PDFs. Require VLM/OCR. Business artifacts — not explicit deletion verdicts.

| File | Origin | Content |
|---|---|---|
| account_history_report_20260718.pdf | account_history_service | Account lifecycle history |
| delivery_correction_attachment.pdf | support_platform | Support attachment with PII (delivery correction) |
| legal_retention_register_20260529.pdf | legal_retention_service | Active legal hold records |
| security_retention_extract.pdf | security_service | Security audit records within retention period |

User link: name, email, phone, account IDs in document text.

---

### 2.5 evidence/images/ — PNG screenshots

Format: PNG. Application UI screenshots. Require VLM.

| File | Origin | Content |
|---|---|---|
| account_admin_console_20260926.png | account_admin_portal | Admin view of account records |
| analytics_profile_view_20260713.png | analytics_platform | Analytics profile record |
| backup_restore_console_20260429.png | backup_service | Backup restore policy panel |
| connector_management_console_20260807.png | integration_admin | Data connectors (enabled/disabled status) |
| customer_export_console_20260618.png | export_service | Export jobs list |
| deleted_account_reference_20260310.png | identity_service | Tombstone / deleted-account reference view |
| marketing_profile_console.png | marketing_platform | Marketing profile (email, consent flags) |
| object_storage_browser_20260213.png | object_storage | Object storage (exports, backups) |
| search_index_inspector_20260901.png | search_index_admin | Search index record |
| security_audit_explorer_20260905.png | security_service | Security audit event viewer |
| support_ticket_console_20260524.png | support_platform | Support ticket viewer |

User link: email, name, account reference visible in UI.

---

## 3. Cross-Cutting Identifier Types

| Identifier | Where found | Notes |
|---|---|---|
| user_id (user_NNN) | All files | Stable — never changes even after deletion |
| email | All systems | Current or historical; case-insensitive (some systems store UPPERCASE) |
| email_hash (SHA-256) | identities, audit log, analytics, tombstones | Changes when email changes; old hashes in audit log |
| phone | identities, audit log, SQL records, support attachments | Format varies by country |
| name | identities, account profiles, tombstones | Full name; direct identifier |
| resource_id | All evidence | account_NNN, search_NNN, analytics_NNN, audit_record_NNN, tombstone_NNN, data_flow_NNN, export_NNN, backup_NNN, support_NNN, cache_NNN, marketing_NNN |
| activity_id (activity_NNN) | system_activity.csv | Can be cited as evidence_id in steps |
| audit_id (audit_NNN) | user_audit_log.csv | Can be cited as evidence_id in steps |
| file_id (evidence_NN) | evidence_files.csv | Primary evidence citation mechanism |

---

## 4. Canonical system_id Values (from sample_output.csv)

| system_id | Resource prefix |
|---|---|
| account_service | account_NNN |
| identity_service | tombstone_NNN |
| search_service | search_NNN |
| analytics_platform | analytics_NNN |
| support_platform | support_NNN |
| export_service | export_NNN |
| backup_service | backup_NNN |
| integration_service | data_flow_NNN |
| security_service | audit_record_NNN |
| marketing_platform | marketing_NNN |
| cache_service | cache_NNN |

---

## 5. Temporal Constraint

All evidence must be evaluated at or before the case's audit_at timestamp.
Evidence captured after that timestamp must not influence the verdict for that case.
