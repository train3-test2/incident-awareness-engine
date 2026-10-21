# R1 local video signal v0.1

## Scope

This is a `demo_only` display contract for the internal-evaluation video. It is not
canonical Evidence, FusionResult, DecisionResult, causal availability, TTSD, or a
source-completeness claim.

The detector never reads an unacknowledged spool message. It calls
`load_accepted_spool_message()` with the immutable EventChunk and the Role3
post-commit ack that binds the exact message path and SHA-256. PostgreSQL remains the
acceptance authority; the payload is recovered from the acknowledged immutable spool
because `r1_stream_events` stores Event identity and content hash rather than the full
NormalizedEvent.

Every accepted EventChunk must match the requested Run and the single
`R1-TGTA/sysmon/Microsoft-Windows-Sysmon/Operational` partition. A different Run,
source/channel, partition, duplicate chunk identity, or sequence gap is an input error;
the detector never silently converts it into a non-match.

## Match rule

The display changes to `demo_rule_match` only when all conditions hold:

1. a complete ProcessGuid lineage is reconstructed from the registered policy root to
   the terminal PowerShell;
2. the complete observed lineage differs from
   `r1-wmi-management-approved-lineage/v0.1`;
3. the same terminal ProcessGuid owns a later Sysmon network Event to the configured
   Target-B IP and TCP port 8443;
4. exactly one candidate satisfies the rule.

An approved Normal lineage with the same network follow-on produces
`condition_not_met`. A process name or an EID 3 by itself never produces a match.
Multiple candidates produce `input_error` rather than selecting one.

## Role1 interface

The detector atomically writes one mutable JSON file. Role1 owns the Dashboard and may
serve or proxy this payload without changing its fields.

A synthetic, schema-valid Attack display payload is provided in
`docs/demo/r1-local-video-signal.example.json`. It is an interface fixture only and
must never be shown as a real Run result.

If an accepted message fails path, hash, schema, sequence, or policy validation, the
detector removes any previous output before it exits. The Dashboard must treat a
missing file as unavailable input and must not retain a previous Match state.

Required display fields include:

- `state`: `observing`, `condition_not_met`, `demo_rule_match`, or `input_error`;
- accepted chunk/Event counts and the last Role3 `accepted_at`;
- policy ID, version, canonical hash, lifecycle, and approved lineage;
- observed lineage, ProcessGuid, destination, Event IDs, and source RecordIds;
- fixed `demo_only` data class and non-guarantees;
- `canonical_result: null`, which prevents the display state from pretending to be an
  official result.

Recommended labels:

- Attack: `DEMO_RULE_MATCH`;
- Normal: `현재 관측된 이벤트에서 Demo 조건 미충족`;
- never label this payload `DETECTED` or a canonical decision.

## Command

```powershell
$env:INCIDENT_AWARENESS_EVENT_TYPES_PATH = '<repo>\configs\event_types_v0.2.yaml'
uv run --frozen python -m incident_awareness.demo.r1_live_signal `
  --spool-root '<spool>\<run-id>' `
  --run-id '<run-id>' `
  --destination-ip '192.168.34.30' `
  --destination-port 8443 `
  --output '<demo-root>\demo-state.json' `
  --watch `
  --poll-seconds 1
```

Run it only against an original-path, Track-B-only accepted spool. Do not point it at
Track A while a formal Run owns the Controller DB and spool.

The post-commit ack binds the absolute Controller spool path. A copied export is
therefore expected to fail validation at a different path; do not rewrite the ack to
make offline replay pass. Live video validation must run against the original accepted
spool, while exported packages remain read-only evidence for later inspection.
