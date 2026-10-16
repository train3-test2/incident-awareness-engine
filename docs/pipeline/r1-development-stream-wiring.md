# R1 WMI development incremental stream wiring

This wiring connects the existing v0.1 stream model, Role3 ingress and append-only
PostgreSQL ledger. It does not replace the whole-JSONL #228 SQS path and does not
change Role4 finality. In particular, the WMI candidate boundary remains A04
(`run_end`, currently t+720); this wiring alone cannot produce a verified close or
causal detection inside the 600-second evaluation horizon.

## Runtime path and authority

`r1-incremental-sysmon-producer.ps1` runs beside the WMI runner. It queries the
live Target-A Sysmon channel, not the completed EVTX/JSONL export. Each response
is saved as an immutable raw JSONL segment and passed to the existing Sysmon
normalizer. The Python command publishes, in order:

1. `R1EventChunk` files under `<spool>/<run_id>/outbox/`;
2. `R1SourceWatermark` files after the query completes;
3. one `R1RunClosed` only after the runner's A04 control record exists and the
   final watermark covers that boundary.

The consumer commits each message through `R1StreamIngress` and
`R1StreamDeliveryRepository` before writing its ack. The file spool is only a
transport. PostgreSQL is the acceptance authority. A crash after DB commit but
before ack is recovered by exact replay; reused identity/sequence with different
content, gaps, late Events, unsupported partitions and host mismatch fail closed.

The raw segment number and 1-based line number become `raw_ref.segment_no` and
`raw_ref.record_no`; Sysmon `RecordId` remains `raw_ref.source_record_id`. The
producer records `ingest_time` as the Controller reception time immediately after
the live query returns. Target-A query completion time is preserved as separate
capture metadata. Incomplete raw/capture pairs are cleaned up on restart recovery
so only verified complete pairs are replayed.

## Required configuration and commands

The cadence values are explicit operator inputs, not validated production
defaults. Before an actual development run, Role3 and the collection owner must
approve `PollIntervalSec`, `ChunkMaxEvents` and `AllowedLatenessMs`. The watermark
is derived from the verified source channel cursor time minus the configured allowed
lateness, never from wall-clock timeout or max Event time. Final watermark and
`run_closed` require verified source drain (the Target-A Sysmon channel cursor reaching
or passing the candidate boundary and all records retrieved). If the runner fails,
`run-failed.json` is published atomically and the sidecar terminates without close.

Render the existing required-partition contract with the runner-verified host:

```powershell
$env:PYTHONPATH = "src"
uv run python -m incident_awareness.pipeline.r1_stream_wiring render-contract `
  --target-host $TargetHost `
  --output "$SpoolRoot\contracts\$RunId-required-partitions.json"
```

Set `INCIDENT_AWARENESS_DATABASE_URL` to the migrated Role3 PostgreSQL database
and run `$env:PYTHONPATH="src"; uv run python -m incident_awareness.storage.migrate` before either
process. No database credential is written to the spool, logs or exports.
Start the sidecar before the runner so pre-Run WmiPrvSE ancestry is retained:

```powershell
scenarios\R1\r1-incremental-sysmon-producer.ps1 `
  -RunId $RunId -TargetHost $TargetHost -TargetAddress $TargetAddress `
  -WinRmPort $WinRmPort -Credential $Credential `
  -ContextStartUtc $TargetBootUtc -SpoolRoot $SpoolRoot `
  -ControlRoot $ControlRoot `
  -RequiredPartitionContract "$SpoolRoot\contracts\$RunId-required-partitions.json" `
  -PollIntervalSec 5 -ChunkMaxEvents 200 -AllowedLatenessMs 2000
```

Run the existing WMI command with the additive control root:

```powershell
scenarios\R1\attack\run.ps1 <existing arguments> `
  -IncrementalStreamControlRoot $ControlRoot
```

The normal command uses the same parameter. The runner publishes `run-started`
after the target supplies `start_time`, and `candidate-boundary-completed` only
after A04 succeeds. These controls do not modify `run_metadata.json`.

If producer and consumer are separated, pass `-NoConsume` and run:

```powershell
uv run python -m incident_awareness.pipeline.r1_stream_wiring consume `
  --spool-root "$SpoolRoot\$RunId" `
  --required-partition-contract "$SpoolRoot\contracts\$RunId-required-partitions.json" `
  --target-host $TargetHost
```

## Stored inputs and Role2/Role4 handoff

- raw segments: `<spool>/<run_id>/raw-segments/sysmon-NNNNNNNN.jsonl` and its
  immutable `.capture.json` actual observation-time companion
- immutable messages: `<spool>/<run_id>/outbox/`
- post-commit acks: `<spool>/<run_id>/acks/`
- late-event records: `<spool>/<run_id>/dead-letter/`
- producer restart state: `<spool>/<run_id>/producer-state.json`
- accepted close export:
  `<spool>/<run_id>/exports/<run_id>/accepted-run-closed.json`
- rendered contract: `<spool>/contracts/<run_id>-required-partitions.json`

The accepted-close export contains the exact `R1RunClosed`, the ledger-loaded
`R1AcceptedRunCloseReceipt`, and the strictly bound contract path, hash and digest.
Role4 loads the typed values with `load_close_export()` (which verifies the required-partition
contract linkage fail-closed) and supplies them to the existing seal/proof API; it must
not reconstruct a close. Role2 uses the same export, contract and durable ledger receipt
at its existing checkpoint/availability boundary. For chunks and watermarks it calls
`load_accepted_spool_message(outbox_path, ack_path)`; this refuses unacknowledged
or changed bytes, then returns the existing typed stream model that
`R1IncrementalEvidenceState.accept_chunk()` consumes. `emitted_at`, ledger
acceptance, proof validation and Evidence-ready times retain their separate
meanings.

The handoff imports are executable and use no parallel receipt authority:

```python
from pathlib import Path
from incident_awareness.pipeline.r1_stream_wiring import (
    load_accepted_spool_message,
    load_close_export,
)

chunk = load_accepted_spool_message(Path(chunk_path), Path(chunk_ack_path))
run_closed, accepted_close_receipt = load_close_export(Path(close_export_path))
# Role2: state.accept_chunk(chunk), then state.accept_run_closed(run_closed)
# Role4: pass run_closed and accepted_close_receipt to the existing seal/proof API.
```

## Rehearsal and remaining operational validation

`tests/pipeline/test_r1_stream_wiring.py` is the reproducible, non-official
fixture rehearsal. It covers normalize → spool → ingress → committed receipt →
export, ack-loss replay, sequence gaps, content mutation and host binding. It is
not a VM collector validation and issues no official Run/Pair ID. A real Windows
Target-A/WinRM run is still required to validate query load, clock comparability,
approved cadence/lateness and service-account permissions.
