"""Validate local samples with the backend schema and verify serving isolation."""

import importlib.util
import json
import shutil
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from incident_awareness.dashboard.telemetry_read_model import PipelineTelemetryResponse

PREVIEW = Path(__file__).resolve().parent
REPOSITORY = PREVIEW.parents[2]


def test_samples_satisfy_the_complete_backend_response_schema() -> None:
    # Given
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to validate the JS Preview generator")
    script = (
        "import {buildPreviewPayload, SCENARIOS} from "
        "'./tests/dashboard/preview/telemetry-preview-model.mjs';"
        "console.log(JSON.stringify(SCENARIOS.flatMap(scenario => "
        "[0, 5, 15, 65, 305].map(time => buildPreviewPayload(time, scenario)))));"
    )
    # When
    result = subprocess.run(
        [node, "--input-type=module", "-e", script],
        cwd=REPOSITORY,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    samples = json.loads(result.stdout)
    # Then
    assert len(samples) == 55
    for sample in samples:
        response = PipelineTelemetryResponse.model_validate(sample)
        assert response.scope == "reported"
        assert response.input_scope == "validated_batch_admission"
        assert response.processing_scope == "normalization_and_evidence"
        assert response.range_end > response.range_start
        assert len(response.points) <= 300


def test_local_server_serves_only_allowlisted_static_files() -> None:
    # Given
    spec = importlib.util.spec_from_file_location("telemetry_preview_server", PREVIEW / "serve.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.PreviewHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        # When
        with urlopen(base, timeout=2) as response:
            content = response.read().decode("utf-8")
            policy = response.headers["Content-Security-Policy"]
        # Then
        assert "시연용 샘플 데이터 · 실제 관측 아님" in content
        assert "connect-src 'none'" in policy
        for path in (
            "/operations/telemetry?scope=reported&window_seconds=300&resolution_seconds=1",
            "/runs",
            "/dashboard",
            "/.env",
            "/tests/dashboard/preview/serve.py",
            "/tests/dashboard/preview/../../../.env",
        ):
            with pytest.raises(HTTPError) as error:
                urlopen(base + path, timeout=2)
            assert error.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
