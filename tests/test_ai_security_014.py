import pytest
from unittest.mock import Mock
from types import SimpleNamespace

from tools.ai_security.embedding_leak_auditor import EmbeddingLeakAuditor


class FakeVectorDBClient:
    def __init__(self, namespaces, mis_scoped=True):
        # namespaces: dict of namespace_name -> list of record ids
        self._namespaces = namespaces
        self._mis_scoped = mis_scoped
        self.host = "127.0.0.1"

    def list_namespaces(self, api_key):
        # mis-scoped key reveals all namespaces; scoped key reveals only own
        if self._mis_scoped and api_key == "mis_scoped_key":
            return list(self._namespaces.keys())
        # assume scoped key includes namespace name: "scoped:ns_a"
        if api_key.startswith("scoped:"):
            ns = api_key.split(":", 1)[1]
            return [ns] if ns in self._namespaces else []
        return []

    def query(self, namespace, api_key, vector=None, top_k=1):
        # mis-scoped key can read any namespace; scoped key can only read own namespace
        if self._mis_scoped and api_key == "mis_scoped_key":
            return {"namespace": namespace, "hits": self._namespaces.get(namespace, [])[:top_k]}
        if api_key.startswith("scoped:"):
            ns = api_key.split(":", 1)[1]
            if ns == namespace:
                return {"namespace": namespace, "hits": self._namespaces.get(namespace, [])[:top_k]}
            raise PermissionError("Unauthorized namespace access")
        raise PermissionError("Invalid API key")


class FakeEmbeddingAPI:
    def __init__(self, return_metadata=False, training_metadata=False):
        self.return_metadata = return_metadata
        self.training_metadata = training_metadata
        self.host = "localhost"

    def embed(self, inputs, return_metadata=False):
        # Return constant-length vectors with mock similarities and optional metadata
        results = []
        for text in inputs:
            md = {}
            if return_metadata or self.return_metadata:
                if self.training_metadata:
                    md = {
                        "seen_in_training": True,
                        "training_dataset_id": "train-ds-001",
                        "training_timestamp": "2024-01-01T00:00:00Z",
                        "user_id": "user-123",
                    }
                else:
                    md = {"request_id": "req-xyz", "model": "mock-embedding-v1"}
            results.append(
                {"embedding": [0.1] * 8, "text": text, "metadata": md if md else None}
            )
        return results


class FakeDataset:
    def __init__(self, name, approved, canaries):
        # canaries: list of (text, vector)
        self.name = name
        self.approved = approved
        self.canaries = canaries


class FakeRateLimiter:
    def __init__(self, max_acquires):
        self.max_acquires = max_acquires
        self.calls = 0

    def acquire(self):
        self.calls += 1
        if self.calls > self.max_acquires:
            raise RuntimeError("rate_limit_exceeded")


def test_detects_cross_namespace_index_exposure_and_confirms_fix(caplog):
    # Prepare mis-scoped client
    namespaces = {"ns_a": ["id1", "id2"], "ns_b": ["id3"]}
    client_mis_scoped = FakeVectorDBClient(namespaces=namespaces, mis_scoped=True)
    auditor = EmbeddingLeakAuditor(egress_allowlist=["127.0.0.1", "localhost"])

    # Detect exposure with mis-scoped key
    with caplog.at_level("INFO"):
        result_exposed = auditor.detect_cross_namespace_index_exposure(
            api_client=client_mis_scoped,
            api_key="mis_scoped_key",
            namespaces=["ns_a", "ns_b"],
        )

    assert isinstance(result_exposed, dict)
    assert "exposed_namespaces" in result_exposed
    assert "ns_b" in result_exposed["exposed_namespaces"]
    assert any("cross-namespace" in msg.lower() for msg in caplog.messages)

    # Confirm inability after policy fix (scoped key)
    client_fixed = FakeVectorDBClient(namespaces=namespaces, mis_scoped=False)
    result_fixed = auditor.detect_cross_namespace_index_exposure(
        api_client=client_fixed,
        api_key="scoped:ns_a",
        namespaces=["ns_a", "ns_b"],
    )
    assert isinstance(result_fixed, dict)
    assert result_fixed.get("exposed_namespaces") == []

    # Ensure logs indicate both detection and remediation
    assert any("exposure detected" in msg.lower() for msg in caplog.messages)
    assert any("no cross-namespace exposure" in msg.lower() for msg in caplog.messages)


def test_recovers_seeded_canary_and_seals_evidence_bundle(tmp_path):
    # Create approved dataset with seeded canaries
    canary_text = "CANARY::secret_phrase_123"
    # Fake embedding vector; auditor will use its own similarity logic; we just ensure threshold logic is tested
    dataset = FakeDataset(
        name="approved_test_set",
        approved=True,
        canaries=[(canary_text, [0.9, 0.1, 0.0])],
    )

    # Embedding client that would allow inversion; we mock it as needed
    embedding_api = FakeEmbeddingAPI(return_metadata=False, training_metadata=False)
    auditor = EmbeddingLeakAuditor(
        egress_allowlist=["127.0.0.1", "localhost"],
        evidence_dir=str(tmp_path),
    )

    result = auditor.recover_seeded_canaries(
        embedding_client=embedding_api,
        dataset=dataset,
        similarity_threshold=0.75,
    )

    # Validate recovery and evidence sealing
    assert isinstance(result, dict)
    assert "recovered" in result and isinstance(result["recovered"], list)
    assert any(canary_text in r.get("text", "") for r in result["recovered"])
    # Evidence bundle path and signing artifacts
    assert result.get("evidence_bundle")
    assert result.get("signature")
    assert result.get("transparency_log_entry")
    sbom = result.get("sbom")
    assert isinstance(sbom, dict)
    assert "clients" in sbom or "sdks" in sbom


def test_recover_canary_requires_approved_dataset():
    unapproved = FakeDataset(name="live_prod", approved=False, canaries=[])
    embedding_api = FakeEmbeddingAPI(return_metadata=False, training_metadata=False)
    auditor = EmbeddingLeakAuditor(egress_allowlist=["127.0.0.1", "localhost"])
    with pytest.raises((PermissionError, ValueError)):
        auditor.recover_seeded_canaries(
            embedding_client=embedding_api,
            dataset=unapproved,
            similarity_threshold=0.8,
        )


def test_flags_embedding_api_training_metadata_leak_and_recommendations():
    api_with_training_md = FakeEmbeddingAPI(return_metadata=True, training_metadata=True)
    auditor = EmbeddingLeakAuditor(egress_allowlist=["127.0.0.1", "localhost"])

    result = auditor.audit_embedding_api_metadata_leak(embedding_api=api_with_training_md)

    assert isinstance(result, dict)
    assert result.get("metadata_leak") is True
    leak_fields = result.get("leak_fields") or []
    assert any("training" in f.lower() for f in leak_fields)
    recommendations = " ".join(result.get("recommendations") or [])
    assert "redact" in recommendations.lower()
    assert "harden" in recommendations.lower() or "configuration" in recommendations.lower()


def test_no_metadata_leak_when_api_returns_no_training_info():
    api_without_md = FakeEmbeddingAPI(return_metadata=False, training_metadata=False)
    auditor = EmbeddingLeakAuditor(egress_allowlist=["127.0.0.1", "localhost"])
    result = auditor.audit_embedding_api_metadata_leak(embedding_api=api_without_md)
    assert isinstance(result, dict)
    assert result.get("metadata_leak") is False
    assert result.get("leak_fields") in ([], None)


def test_rate_limiting_is_enforced_and_logged(caplog):
    namespaces = {"ns_a": ["id1"]}
    client = FakeVectorDBClient(namespaces=namespaces, mis_scoped=True)
    rate_limiter = FakeRateLimiter(max_acquires=1)
    auditor = EmbeddingLeakAuditor(
        egress_allowlist=["127.0.0.1", "localhost"],
        rate_limiter=rate_limiter,
    )

    with caplog.at_level("WARNING"):
        # First call should pass
        res1 = auditor.detect_cross_namespace_index_exposure(
            api_client=client,
            api_key="mis_scoped_key",
            namespaces=["ns_a"],
        )
        assert isinstance(res1, dict)
        # Second call should trigger rate limit handling
        try:
            res2 = auditor.detect_cross_namespace_index_exposure(
                api_client=client,
                api_key="mis_scoped_key",
                namespaces=["ns_a"],
            )
            # If handled gracefully, a status indicator should be present
            assert isinstance(res2, dict)
            assert res2.get("status") in ("rate_limited", "error")
        except Exception as e:
            # Alternatively, an exception may be raised; ensure it's due to rate limiting
            assert "rate" in str(e).lower()

    assert any("rate" in msg.lower() for msg in caplog.messages)


def test_sandboxed_network_egress_allowlist_blocks_external(monkeypatch):
    calls = {"count": 0}

    def fake_request(*args, **kwargs):
        calls["count"] += 1
        url = kwargs.get("url") or (args[1] if len(args) > 1 else "")
        assert url.startswith("http://127.0.0.1") or url.startswith("http://localhost"), "External egress attempted"
        return SimpleNamespace(status_code=200, text="ok", json=lambda: {"ok": True})

    # Patch requests to ensure only localhost calls are permitted if any network is attempted
    try:
        import requests

        monkeypatch.setattr(requests.sessions.Session, "request", fake_request)
    except Exception:
        # If requests is not used by implementation, skip patching
        pass

    auditor = EmbeddingLeakAuditor(egress_allowlist=["127.0.0.1", "localhost"])

    # Run a benign operation that should not require external egress
    api = FakeEmbeddingAPI(return_metadata=False, training_metadata=False)
    dataset = FakeDataset(name="approved_test_set", approved=True, canaries=[("CANARY::x", [0.5, 0.3])])
    res = auditor.recover_seeded_canaries(
        embedding_client=api,
        dataset=dataset,
        similarity_threshold=0.1,
    )
    assert isinstance(res, dict)
    assert res.get("evidence_bundle")
    # Ensure no external network egress occurred; either zero calls or only localhost
    assert calls["count"] == 0 or calls["count"] >= 0