import pytest
import types

from tools.cloud import iam_attack_path_mapper as mapper_mod


class FakeRateLimitError(Exception):
    pass


class FakePermissionError(Exception):
    def __init__(self, missing_permissions):
        super().__init__("Missing read permissions")
        self.missing_permissions = set(missing_permissions)

    def __str__(self):
        return f"Missing read permissions: {sorted(self.missing_permissions)}"


class FakeCloudClient:
    def __init__(self, dataset, fail_missing_perms=False, throttle_times=0):
        # dataset: {account_id: {"roles": {role_name: {"trust": trust_doc, "inline": [actions], "managed": [actions]}}}}
        self.dataset = dataset
        self.fail_missing_perms = fail_missing_perms
        self.throttle_times = throttle_times
        self.read_calls = []
        self.write_calls = []
        self.secret_fetch_calls = 0
        self.scoped_accounts_seen = set()

    def _maybe_throttle(self):
        if self.throttle_times > 0:
            self.throttle_times -= 1
            raise FakeRateLimitError("Rate exceeded")

    def _maybe_fail_perms(self, required):
        if self.fail_missing_perms:
            raise FakePermissionError(required)

    def list_accounts(self, scoped_accounts=None):
        self.read_calls.append(("list_accounts", tuple(scoped_accounts) if scoped_accounts else None))
        self._maybe_throttle()
        # Honor scope strictly
        if scoped_accounts is None:
            # if None, return none to enforce scoping required
            return []
        for aid in scoped_accounts:
            self.scoped_accounts_seen.add(aid)
        return list(scoped_accounts)

    def list_roles(self, account_id):
        self.read_calls.append(("list_roles", account_id))
        self._maybe_throttle()
        self._maybe_fail_perms({"iam:ListRoles"})
        roles = self.dataset.get(account_id, {}).get("roles", {})
        return [{"account_id": account_id, "name": rn} for rn in roles.keys()]

    def get_role_trust_policy(self, account_id, role_name):
        self.read_calls.append(("get_role_trust_policy", account_id, role_name))
        self._maybe_throttle()
        self._maybe_fail_perms({"iam:GetRole"})
        return self.dataset[account_id]["roles"][role_name].get("trust", {})

    def get_role_inline_policies(self, account_id, role_name):
        self.read_calls.append(("get_role_inline_policies", account_id, role_name))
        self._maybe_throttle()
        self._maybe_fail_perms({"iam:ListRolePolicies", "iam:GetRolePolicy"})
        return list(self.dataset[account_id]["roles"][role_name].get("inline", []))

    def get_role_managed_policies(self, account_id, role_name):
        self.read_calls.append(("get_role_managed_policies", account_id, role_name))
        self._maybe_throttle()
        self._maybe_fail_perms({"iam:ListAttachedRolePolicies"})
        return list(self.dataset[account_id]["roles"][role_name].get("managed", []))

    def get_secret_value(self, *args, **kwargs):
        # Should never be called
        self.secret_fetch_calls += 1
        raise AssertionError("Secret values must not be retrieved by the tool (metadata only)")

    def __getattr__(self, name):
        # Any write/modification method should not be called; guard common prefixes
        write_prefixes = ("put_", "delete_", "update_", "create_", "attach_", "detach_", "add_", "remove_", "set_")
        if name.startswith(write_prefixes):
            def _writer(*a, **kw):
                self.write_calls.append((name, a, kw))
                raise AssertionError(f"Write operation '{name}' must not be invoked (read-only requirement)")
            return _writer
        raise AttributeError(name)


def _create_mapper(config, client, monkeypatch):
    # Try different construction/injection patterns
    MapperClass = getattr(mapper_mod, "IAMAttackPathMapper", None)
    mapper = None
    if MapperClass is not None:
        # Try passing client in constructor
        try:
            mapper = MapperClass(config, client=client)
        except TypeError:
            try:
                mapper = MapperClass(config)
            except TypeError:
                mapper = MapperClass()
        # Try setting client via attribute or method
        if hasattr(mapper, "set_client"):
            mapper.set_client(client)
        elif hasattr(mapper, "client"):
            setattr(mapper, "client", client)
        else:
            # Try setting module-level factory or client
            if hasattr(mapper_mod, "get_client"):
                monkeypatch.setattr(mapper_mod, "get_client", lambda conf: client, raising=False)
            if hasattr(mapper_mod, "CLIENT"):
                monkeypatch.setattr(mapper_mod, "CLIENT", client, raising=False)
            if hasattr(mapper, "client_factory"):
                mapper.client_factory = lambda conf: client
    else:
        # Fall back to function-oriented API
        if hasattr(mapper_mod, "get_client"):
            monkeypatch.setattr(mapper_mod, "get_client", lambda conf: client, raising=False)
        if hasattr(mapper_mod, "CLIENT"):
            monkeypatch.setattr(mapper_mod, "CLIENT", client, raising=False)
        # Use a simple namespace to hold config/reference if needed
        mapper = types.SimpleNamespace(config=config, client=client)
    return mapper


def _run_scan(mapper, client, monkeypatch):
    # Try different scan entrypoints
    if hasattr(mapper, "scan"):
        return mapper.scan()
    if hasattr(mapper_mod, "run_scan"):
        try:
            return mapper_mod.run_scan(getattr(mapper, "config", {}), client=client)
        except TypeError:
            return mapper_mod.run_scan(getattr(mapper, "config", {}))
    if hasattr(mapper_mod, "scan"):
        try:
            return mapper_mod.scan(getattr(mapper, "config", {}), client=client)
        except TypeError:
            return mapper_mod.scan(getattr(mapper, "config", {}))
    raise RuntimeError("No scan entrypoint found in tools.cloud.iam_attack_path_mapper")


def _snapshot(mapper, client, monkeypatch):
    # Try snapshot/build_baseline
    if hasattr(mapper, "build_baseline"):
        return mapper.build_baseline()
    if hasattr(mapper, "snapshot"):
        return mapper.snapshot()
    if hasattr(mapper_mod, "build_baseline"):
        return mapper_mod.build_baseline(getattr(mapper, "config", {}))
    if hasattr(mapper_mod, "snapshot"):
        return mapper_mod.snapshot(getattr(mapper, "config", {}))
    # Fallback: just run a scan and consider it a snapshot
    return _run_scan(mapper, client, monkeypatch)


def _diff(mapper, old, new):
    # Try different diff functions
    if hasattr(mapper, "diff"):
        return mapper.diff(old, new)
    if hasattr(mapper, "detect_drift"):
        return mapper.detect_drift(old, new)
    if hasattr(mapper_mod, "diff_snapshots"):
        return mapper_mod.diff_snapshots(old, new)
    if hasattr(mapper_mod, "diff"):
        return mapper_mod.diff(old, new)
    raise RuntimeError("No diff/drift entrypoint found")


def _get_field(obj, *path, default=None):
    cur = obj
    for key in path:
        if isinstance(cur, dict):
            if key in cur:
                cur = cur[key]
                continue
            return default
        # object attribute access
        if hasattr(cur, key):
            cur = getattr(cur, key)
            continue
        # Not found
        return default
    return cur


def _extract_attack_paths(result):
    # Try common locations/keys
    candidates = [
        lambda r: _get_field(r, "attack_paths"),
        lambda r: _get_field(r, "graph", "paths"),
        lambda r: _get_field(r, "paths"),
        lambda r: _get_field(r, "results", "attack_paths"),
    ]
    for c in candidates:
        v = c(result)
        if v:
            return v
    return []


def _extract_remediations(result):
    candidates = [
        lambda r: _get_field(r, "remediations"),
        lambda r: _get_field(r, "results", "remediations"),
        lambda r: _get_field(r, "advice"),
    ]
    for c in candidates:
        v = c(result)
        if v:
            return v
    return []


def _find_path(paths, src_name, dst_name=None, dst_privilege=None):
    for p in paths:
        # Normalize to dict-like
        frm = _get_field(p, "from") or _get_field(p, "src") or _get_field(p, "start")
        to = _get_field(p, "to") or _get_field(p, "dst") or _get_field(p, "end")
        priv = _get_field(p, "privilege") or _get_field(p, "target_privilege") or _get_field(p, "impact")
        if isinstance(frm, dict):
            frm = frm.get("name") or frm.get("id")
        if isinstance(to, dict):
            to = to.get("name") or to.get("id")
        if frm and frm.endswith(src_name):
            if dst_name and to and to.endswith(dst_name):
                return p
            if dst_privilege and priv and dst_privilege.lower() in str(priv).lower():
                return p
    return None


@pytest.fixture
def misconfigured_tenant_dataset():
    # Build dataset with a misconfigured trust chain: role_low -> role_intermediate -> role_admin (AdministratorAccess)
    account = "111111111111"
    roles = {
        "role_low": {
            "trust": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}]},
            "inline": ["logs:DescribeLogStreams"],
            "managed": [],
        },
        "role_intermediate": {
            # Misconfigured trust: allows role_low to assume it
            "trust": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:role/role_low"}, "Action": "sts:AssumeRole"}]},
            "inline": ["iam:PassRole", "sts:AssumeRole"],
            "managed": [],
        },
        "role_admin": {
            # Trusted by role_intermediate
            "trust": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:role/role_intermediate"}, "Action": "sts:AssumeRole"}]},
            "inline": ["AdministratorAccess"],  # marker to indicate admin privileges
            "managed": ["AdministratorAccess"],
        },
    }
    return {account: {"roles": roles}}


@pytest.fixture
def drift_dataset_initial():
    account = "222222222222"
    roles = {
        "role_dev": {
            "trust": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
            "inline": ["s3:ListBucket"],
            "managed": [],
        },
    }
    return {account: {"roles": roles}}


@pytest.fixture
def drift_dataset_after_change():
    account = "222222222222"
    roles = {
        "role_dev": {
            "trust": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
            # New inline permission added
            "inline": ["s3:ListBucket", "s3:GetObject"],
            "managed": [],
        },
    }
    return {account: {"roles": roles}}


def test_attack_path_identified_and_prioritized_remediation(monkeypatch, misconfigured_tenant_dataset):
    # Arrange
    scope_accounts = ["111111111111"]
    fake = FakeCloudClient(misconfigured_tenant_dataset)
    config = {"scope": {"accounts": scope_accounts}, "read_only": True}
    mapper = _create_mapper(config, fake, monkeypatch)

    # Use scoped accounts through possible API points
    if hasattr(mapper, "set_scope"):
        mapper.set_scope(scope_accounts)
    elif hasattr(mapper, "scope"):
        mapper.scope = {"accounts": scope_accounts}
    elif hasattr(mapper_mod, "DEFAULT_SCOPE"):
        monkeypatch.setattr(mapper_mod, "DEFAULT_SCOPE", {"accounts": scope_accounts}, raising=False)

    # Act
    result = _run_scan(mapper, fake, monkeypatch)

    # Assert read-only behavior
    assert not fake.write_calls, "Tool must not perform write/modify/delete operations"

    # Assert scope honored
    assert fake.scoped_accounts_seen.issubset(set(scope_accounts)), "Tool must only access specified accounts"
    assert fake.scoped_accounts_seen == set(scope_accounts), "Tool should access all and only specified accounts"

    # Assert no secret access attempted
    assert fake.secret_fetch_calls == 0, "Tool must not retrieve secret values"

    # Assert attack path exists
    paths = _extract_attack_paths(result)
    assert isinstance(paths, (list, tuple)) and len(paths) > 0, "Expected at least one attack path"
    path = _find_path(paths, "role_low", dst_name="role_admin") or _find_path(paths, "role_low", dst_privilege="admin")
    assert path is not None, "Expected path from low-privilege role to admin"

    # Steps should indicate AssumeRole chain
    steps = _get_field(path, "steps", default=[])
    text_repr = " ".join(str(s) for s in steps) if steps else str(path)
    assert "AssumeRole" in text_repr or "sts:AssumeRole" in text_repr, "Expected AssumeRole step in attack path"

    # Assert prioritized remediation contains trust policy fix and role names
    remediations = _extract_remediations(result)
    assert remediations, "Expected remediation suggestions"
    # Normalize first item text
    joined = " | ".join(str(r) for r in remediations)
    assert "trust" in joined.lower() or "assume" in joined.lower(), "Remediation should mention trust policy/configuration"
    assert "role_intermediate" in joined and "role_low" in joined, "Remediation should reference involved roles"
    # Check prioritization/severity if available
    severities = [(_get_field(r, "priority") or _get_field(r, "severity") or "").lower() for r in remediations]
    if severities:
        assert any(s in ("high", "critical", "p0", "p1") for s in severities), "Expected high-priority remediation for admin path"


def test_drift_detection_reports_clear_diff(monkeypatch, drift_dataset_initial, drift_dataset_after_change):
    # Arrange initial baseline
    account = "222222222222"
    scope_accounts = [account]
    fake1 = FakeCloudClient(drift_dataset_initial)
    config = {"scope": {"accounts": scope_accounts}, "read_only": True}
    mapper = _create_mapper(config, fake1, monkeypatch)
    baseline = _snapshot(mapper, fake1, monkeypatch)

    # Change: add inline permission
    fake2 = FakeCloudClient(drift_dataset_after_change)
    # Reuse mapper but switch client if possible
    if hasattr(mapper, "set_client"):
        mapper.set_client(fake2)
    elif hasattr(mapper, "client"):
        mapper.client = fake2
    else:
        # Fallback: reconstruct
        mapper = _create_mapper(config, fake2, monkeypatch)

    # Act
    current = _snapshot(mapper, fake2, monkeypatch)
    drift = _diff(mapper, baseline, current)

    # Assert drift identified and diff contents
    # Check for any drift flag
    drift_flag = _get_field(drift, "drift") or _get_field(drift, "has_drift")
    if drift_flag is not None:
        assert bool(drift_flag) is True
    # Check added permissions and affected identities
    added = _get_field(drift, "added_permissions") or _get_field(drift, "permissions", "added") or []
    affected = _get_field(drift, "affected_identities") or _get_field(drift, "identities") or []
    # Be flexible if nested structures
    added_flat = set()
    if isinstance(added, dict):
        for v in added.values():
            if isinstance(v, (list, tuple, set)):
                added_flat.update(v)
    elif isinstance(added, (list, tuple, set)):
        added_flat.update(added)
    else:
        added_flat.update([str(added)])
    assert any("s3:GetObject" in str(x) for x in added_flat), "Expected added s3:GetObject permission in drift report"
    affected_names = set()
    if isinstance(affected, dict):
        affected_names.update(affected.keys())
        for v in affected.values():
            if isinstance(v, dict) and "name" in v:
                affected_names.add(v["name"])
    elif isinstance(affected, (list, tuple, set)):
        for a in affected:
            if isinstance(a, str):
                affected_names.add(a)
            elif isinstance(a, dict):
                affected_names.add(a.get("name") or a.get("id") or "")
    assert any("role_dev" in n for n in affected_names), "Expected affected identity role_dev"
    # Check textual diff includes + s3:GetObject
    diff_text = _get_field(drift, "diff") or _get_field(drift, "changes", "diff") or ""
    assert "+ s3:GetObject" in str(diff_text), "Expected unified diff showing added permission"


def test_fails_gracefully_when_missing_read_permissions(monkeypatch):
    # Arrange a client that raises permission errors on read calls
    account = "333333333333"
    dataset = {account: {"roles": {}}}
    fake = FakeCloudClient(dataset, fail_missing_perms=True)
    config = {"scope": {"accounts": [account]}, "read_only": True}
    mapper = _create_mapper(config, fake, monkeypatch)

    # Act + Assert
    MissingErr = getattr(mapper_mod, "MissingReadPermissionsError", None)
    with pytest.raises(Exception) as ei:
        _run_scan(mapper, fake, monkeypatch)
    exc = ei.value
    # If the tool wraps into specific error, it should be of that type
    if MissingErr and isinstance(exc, MissingErr):
        missing = getattr(exc, "missing_permissions", None)
        suggestion = getattr(exc, "suggested_actions", None) or getattr(exc, "suggestions", None)
        assert missing and {"iam:ListRoles", "iam:GetRolePolicy"}.intersection(set(missing)), "Should list missing read permissions"
        # Should include least-privilege remediation guidance
        assert suggestion, "Expected least-privilege remediation suggestions"
    else:
        # Generic assertion: exception message lists missing permissions
        msg = str(exc)
        assert "ListRoles" in msg or "GetRolePolicy" in msg or "Missing read permissions" in msg

    # Tool should not attempt any writes or secrets
    assert not fake.write_calls, "Tool must not attempt write operations when failing"
    assert fake.secret_fetch_calls == 0, "Tool must not try to fetch secrets"


def test_respects_rate_limits_and_retries(monkeypatch, misconfigured_tenant_dataset):
    # Arrange: throttle first two reads
    scope_accounts = ["111111111111"]
    fake = FakeCloudClient(misconfigured_tenant_dataset, throttle_times=2)
    config = {"scope": {"accounts": scope_accounts}, "read_only": True, "rate_limit": {"max_calls_per_second": 5}}
    mapper = _create_mapper(config, fake, monkeypatch)

    # Monkeypatch time.sleep to record backoff without delay
    sleeps = []

    def fake_sleep(sec):
        sleeps.append(sec)

    import time
    monkeypatch.setattr(time, "sleep", fake_sleep)

    # Also monkeypatch module-level sleep if used directly
    if hasattr(mapper_mod, "time"):
        monkeypatch.setattr(mapper_mod.time, "sleep", fake_sleep, raising=False)

    # If tool has retry/backoff config, ensure it's enabled through config; already provided

    # Act
    result = None
    try:
        result = _run_scan(mapper, fake, monkeypatch)
    except FakeRateLimitError:
        pytest.fail("Tool should handle throttling by retrying, not propagate rate limit error")

    # Assert that at least one sleep occurred (backoff)
    assert sleeps, "Expected tool to back off (sleep) on rate limiting"
    # Regular assertions: scope and no writes/secrets
    assert fake.scoped_accounts_seen == set(scope_accounts)
    assert not fake.write_calls
    assert fake.secret_fetch_calls == 0
    # Also ensure we still got attack paths or at least a completed result
    assert result is not None

