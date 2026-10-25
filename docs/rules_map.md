# Rules Map — Ghost Data Still Exists

Phase 0 recon. Written 2026-10-24.
Source: dataset/deletion_rules.csv

---

## Rule Table

| rule_id | data_category | condition | required_action |
|---|---|---|---|
| rule_01 | USER_PROFILE | Always | DELETE |
| rule_02 | SECONDARY_IDENTIFIER | Always | DELETE |
| rule_03 | SEARCH_INDEX_ENTRY | Always | DELETE |
| rule_04 | CACHE_ENTRY | Always | DELETE |
| rule_05 | SUPPORT_MESSAGE | Conversation contains shared customer, agent, or order context that must be retained | REDACT |
| rule_06 | SUPPORT_ATTACHMENT | Attachment belongs only to the deletion subject | DELETE |
| rule_07 | ANALYTICS_PROFILE | Record is still attributable to a user | ANONYMIZE |
| rule_08 | PRODUCT_TELEMETRY | Record is still attributable to a user | ANONYMIZE |
| rule_09 | USER_EXPORT | Always | DELETE |
| rule_10 | MARKETING_PROFILE | Always | DELETE |
| rule_11 | EMAIL_DELIVERY_LOG | Log contains a user email address | REDACT |
| rule_12 | SECURITY_AUDIT_LOG | Record is within the supplied retention period | RETAIN |
| rule_13 | LEGAL_HOLD_RECORD | A supplied legal hold is active | RETAIN |
| rule_14 | BACKUP_ARCHIVE | Restore access can be blocked | RETAIN |
| rule_15 | ACCOUNT_TOMBSTONE | Account is deleted and only a stable internal user_id is needed to preserve references to retained records | REDACT |

---

## Per-Rule Detail

### rule_01 — USER_PROFILE → DELETE

System: account_service
Resource prefix: account_NNN
Condition: Always (unconditional).
Treatment: Delete the entire record.
Permitted identifiers on retained records: None — record must not exist.
Notes: The account_service customer profile is the primary identity record.

---

### rule_02 — SECONDARY_IDENTIFIER → DELETE

System: Any system holding a secondary identifier cross-reference.
Resource prefix: varies (could be a secondary identity mapping record).
Condition: Always (unconditional).
Treatment: Delete the entire record.
Permitted identifiers on retained records: None.
Notes: Secondary identifiers include any alias, linked account, or cross-system reference that identifies the user.

---

### rule_03 — SEARCH_INDEX_ENTRY → DELETE

System: search_service
Resource prefix: search_NNN
Condition: Always (unconditional).
Treatment: Delete the entire record.
Permitted identifiers on retained records: None.
Notes: Search index entries expose display_name, email, and customer_reference. All must be removed.

---

### rule_04 — CACHE_ENTRY → DELETE

System: cache_service
Resource prefix: cache_NNN
Condition: Always (unconditional).
Treatment: Delete the entire record.
Permitted identifiers on retained records: None.
Notes: Profile caches reproduce account_service data; must be cleared.

---

### rule_05 — SUPPORT_MESSAGE → REDACT

System: support_platform
Resource prefix: support_NNN (conversation records)
Condition: Conversation contains shared customer, agent, or order context that must be retained.
Treatment: Keep the record but REMOVE direct identifiers from the message_text and subject fields.
Permitted identifiers on retained records: subject_reference (user_id) MAY remain as a stable reference only if required; name, email, phone must be removed.
Retention conditions: The conversation must contain context for another customer, an agent, or an order that cannot be deleted.
Notes: If the conversation belongs only to the deletion subject (no shared context), it falls under rule_06 logic (DELETE). Use REDACT when there is shared context requiring retention.

---

### rule_06 — SUPPORT_ATTACHMENT → DELETE

System: support_platform
Resource prefix: support_NNN (attachment records)
Condition: Attachment belongs only to the deletion subject.
Treatment: Delete the entire attachment record.
Permitted identifiers on retained records: None.
Notes: If an attachment is shared with or belongs to other parties, a separate policy determination is needed. As stated in the rule, the DELETE condition is that it belongs only to the subject.

---

### rule_07 — ANALYTICS_PROFILE → ANONYMIZE

System: analytics_platform
Resource prefix: analytics_NNN
Condition: Record is still attributable to a user (i.e., user_id, email, phone, email_hash fields are non-null).
Treatment: Irreversibly unlink the record from the user (set user_id, email, phone, email_hash to null).
Permitted identifiers on retained records: None of the direct identifiers (user_id, email, phone, email_hash); aggregate metrics and activity events may remain.
Retention conditions: Record itself is retained; only identity linkage is removed.
Notes: An already-anonymized record (all identity fields null) satisfies this rule — VERIFY_RECORD_ANONYMIZED confirms this.

---

### rule_08 — PRODUCT_TELEMETRY → ANONYMIZE

System: telemetry/analytics systems
Resource prefix: varies
Condition: Record is still attributable to a user.
Treatment: Irreversibly unlink from the user.
Permitted identifiers on retained records: None of the direct identifiers.
Notes: Same logic as rule_07 for product/behavioral telemetry data.

---

### rule_09 — USER_EXPORT → DELETE

System: export_service (and object storage)
Resource prefix: export_NNN
Condition: Always (unconditional).
Treatment: Delete the entire export record and the associated export file.
Permitted identifiers on retained records: None.
Notes: Downloadable data export archives must be deleted. An active export download link is also a data exposure risk.

---

### rule_10 — MARKETING_PROFILE → DELETE

System: marketing_platform
Resource prefix: marketing_NNN
Condition: Always (unconditional).
Treatment: Delete the entire record.
Permitted identifiers on retained records: None.

---

### rule_11 — EMAIL_DELIVERY_LOG → REDACT

System: notification_service / email_delivery_service
Resource prefix: email_delivery_NNN
Condition: Log contains a user email address.
Treatment: Keep the log but remove the email address from the record.
Permitted identifiers on retained records: Delivery metadata without email.
Notes: Delivery logs are operational records; the email must be redacted but the log entry may remain.

---

### rule_12 — SECURITY_AUDIT_LOG → RETAIN

System: security_service
Resource prefix: audit_record_NNN
Condition: Record is within the supplied retention period.
Treatment: Retain the full record.
Permitted identifiers on retained records: subject_reference (user_id) — the stable reference is permitted. All other fields (event_name, actor_type, integrity_seal) remain as-is.
Retention conditions: A retention period must be active and the record must fall within it.
Notes: The security audit log is the primary RETAIN case. Every deletion case in the sample output includes VERIFY_RECORD_PRESENT for an audit_record_NNN in security_service.

---

### rule_13 — LEGAL_HOLD_RECORD → RETAIN

System: Any system with legal hold records (evidenced in legal_retention_register_20260529.pdf)
Resource prefix: varies
Condition: A supplied legal hold is active.
Treatment: Retain the full record.
Permitted identifiers on retained records: All identifiers may remain while the hold is active.
Retention conditions: An active legal hold document or order covers the record.

---

### rule_14 — BACKUP_ARCHIVE → RETAIN (with restore blocked)

System: backup_service
Resource prefix: backup_NNN
Condition: Restore access can be blocked.
Treatment: Retain the backup but BLOCK restore of the user's data.
Permitted identifiers on retained records: subject_reference (user_id) in the backup catalog entry; underlying backup data may remain on storage since restore is blocked.
Retention conditions: The backup is retained for system integrity; the restore path specifically for this user must be disabled.
Notes: Finding = REPORT_RESTORE_RISK; Remediation = BLOCK_RESTORE; Verification = VERIFY_RESTORE_BLOCKED.

---

### rule_15 — ACCOUNT_TOMBSTONE → REDACT

System: identity_service
Resource prefix: tombstone_NNN
Condition: Account is deleted and only a stable internal user_id is needed to preserve references to retained records.
Treatment: Keep the tombstone record but REMOVE name, email, phone, email_hash. Only user_id (subject_reference) remains.
Permitted identifiers on retained records: subject_reference (user_id) ONLY. name, email, phone, email_hash must all be null.
Retention conditions: Retained records (e.g., security audit logs) still reference the user_id.
Notes: A correctly redacted tombstone has name=null, email=null, phone=null, email_hash=null, account_status=DELETED, subject_reference=user_NNN.

---

## Action Summary Matrix

| required_action | Step operations used |
|---|---|
| DELETE | REPORT_REMAINING_RECORD (finding) -> DELETE_RECORD (remediation) -> VERIFY_RECORD_ABSENT (verification) |
| REDACT | REPORT_EXPOSED_PII (finding) -> REDACT_RECORD (remediation) -> VERIFY_RECORD_REDACTED (verification) |
| ANONYMIZE | REPORT_EXPOSED_PII (finding) -> ANONYMIZE_RECORD (remediation) -> VERIFY_RECORD_ANONYMIZED (verification) |
| RETAIN | VERIFY_RECORD_PRESENT (verification only — already in correct state) |
| RETAIN + BLOCK | REPORT_RESTORE_RISK (finding) -> BLOCK_RESTORE (remediation) -> VERIFY_RESTORE_BLOCKED (verification) |

---

## Data-Flow and Sync Risks

Active sync/import/restore processes that can recreate deleted data require:
- Finding: REPORT_ACTIVE_DATA_FLOW (state=ACTIVE) or REPORT_RESTORE_RISK (state=ACTIVE)
- Remediation: DISABLE_DATA_FLOW (state=DISABLED) or BLOCK_RESTORE (state=BLOCKED)
- Verification: VERIFY_DATA_FLOW_DISABLED or VERIFY_RESTORE_BLOCKED

Data flows must be DISABLED before their downstream records are remediated (dependency ordering).

Key systems that can be active data flows:
- integration_service (data_flow_NNN) — connector pushing user data to analytics warehouse
- account_service sync jobs — can re-index search entries
- backup_service — restore path can recreate deleted profiles

---

## Completeness Conditions (Concrete Field Checks)

A deletion is COMPLETE when ALL of the following are true as of audit_at:

**Condition 1 — Every relevant copy has the required treatment:**
For each data_category applicable to this user:
  - USER_PROFILE: No record in account_service.customer_profiles with customer_reference = user_id (or historical ids). Check: account_NNN absent in SQL replicas, snapshots, logs (rows=0).
  - SECONDARY_IDENTIFIER: No secondary identifier cross-references found.
  - SEARCH_INDEX_ENTRY: No record in search_service.customer_search_documents with customer_reference = user_id or email. Check: search_NNN absent in SQL/snapshots/logs (result=miss).
  - CACHE_ENTRY: No record in cache_service with user_id.
  - SUPPORT_MESSAGE: message_text and subject fields contain no email/phone/name (redacted); subject_reference only if shared context. Check: message_text = [REDACTED] or similar.
  - SUPPORT_ATTACHMENT: Attachment record absent if it belonged solely to the subject.
  - ANALYTICS_PROFILE: analytics_NNN record exists but user_id/email/phone/email_hash fields = null. Check: all identity fields null in SQL/snapshots.
  - USER_EXPORT: No export_NNN record for user_id. Check: export manifest absent.
  - MARKETING_PROFILE: No marketing_NNN record for user_id.
  - EMAIL_DELIVERY_LOG: email_delivery_NNN records have email field redacted.
  - SECURITY_AUDIT_LOG: audit_record_NNN still present (retained). Check: record exists with subject_reference=user_id.
  - BACKUP_ARCHIVE: backup_NNN record exists but restore_allowed = false. Check: restore_allowed field in backup catalog.
  - ACCOUNT_TOMBSTONE: tombstone_NNN exists with name=null, email=null, phone=null, email_hash=null, subject_reference=user_id.

**Condition 2 — No active sync, import, or restore path can recreate the data:**
  - integration_service.connector_configurations: data_flow_NNN records for this user's email or user_id have enabled = false. Check: enabled field in connector_configurations.
  - backup_service: restore_allowed = false for any backup_NNN referencing this user.
  - No active SYNC_RECORD or INDEX_RECORD activities from system_activity.csv for this user's resources after deletion.

**Condition 3 — Retained records contain only permitted identifiers:**
  - SECURITY_AUDIT_LOG (audit_record_NNN): only subject_reference (user_id), event_name, actor_type, integrity_seal. No email/phone/name.
  - ACCOUNT_TOMBSTONE (tombstone_NNN): only subject_reference (user_id). name/email/phone/email_hash all null.
  - SUPPORT_MESSAGE (when redacted): no email/phone/name in message_text.

**Condition 4 — Records that must be retained still exist:**
  - SECURITY_AUDIT_LOG: audit_record_NNN with subject_reference = user_id present in evidence (SQL/snapshot/log).
  - LEGAL_HOLD_RECORD: relevant records still present if legal hold active.
  - ACCOUNT_TOMBSTONE: tombstone_NNN exists (redacted) if referenced by retained records.

---

## NOT_APPLICABLE Expression

NOT_APPLICABLE is used when the request_text does NOT authorize deletion.

Situations that yield NOT_APPLICABLE:
- request_text is a request for data access, data export, correction, marketing opt-out, complaint, or any non-deletion action.
- request_text is ambiguous and cannot be interpreted as a deletion request.

NOT_APPLICABLE cases:
- deletion_status = NOT_APPLICABLE
- steps_json = [] (empty JSON array)
- Example row: case_000,NOT_APPLICABLE,[]

In the data, NOT_APPLICABLE is expressed purely by the output format — there is no NOT_APPLICABLE value in the input fields. The determination is made solely from evaluating request_text.

Note: reported_status from the deletion workflow is NOT a reliable signal for NOT_APPLICABLE.
Even a case with reported_status=NOT_STARTED must be evaluated against request_text independently.
