import pathlib, json, textwrap, sys
from datetime import datetime
from agent.tools import read_backlog, pick_next_ticket, git, run_cmd, call_llm, apply_patches
from agent.policies import MAX_RETRIES, MAX_CHANGED_LINES_DEFAULT

REPO = pathlib.Path(__file__).resolve().parents[1]

def read_allowed_files(ticket: dict, paths: list[str] | None = None) -> str:
    """Read current contents of allow-listed files to provide context to the LLM."""
    content_parts = []
    target_paths = paths if paths is not None else ticket.get('area_allowlist', [])
    for file_path in target_paths:
        try:
            full_path = REPO / file_path
            if full_path.exists() and full_path.is_file():
                content = full_path.read_text(encoding='utf-8')
                content_parts.append(f"--- {file_path} ---\n{content}")
        except Exception:
            # Ignore unreadable files; context is best-effort
            pass
    return "\n\n".join(content_parts)

def _sanitize_ticket_id(ticket_id: str) -> str:
    """Create a filesystem- and import-friendly suffix for filenames from the ticket id.
    e.g., FEAT-001 -> feat_001
    """
    safe = ticket_id.lower().replace('-', '_')
    # strip any characters outside [a-z0-9_]
    safe = ''.join(ch for ch in safe if (ch.isalnum() or ch == '_'))
    return safe

def write_tests(ticket):
    safe_id = _sanitize_ticket_id(ticket['id'])
    fname = (REPO / 'tests' / f"test_{safe_id}.py")
    fname.parent.mkdir(parents=True, exist_ok=True)
    prompt = textwrap.dedent('''
    Write pytest tests for this feature, minimal and focused.
    Acceptance criteria:
    {criteria}
    Project layout uses "src" layout at src/your_package/.
    At the top of the test, add:
        import sys, pathlib
        sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
    so that `import your_package` works during pytest.
    Only write Python code for pytest in one file. No prose.
    ''').format(criteria=json.dumps(ticket['acceptance_tests'], indent=2))
    test_code = call_llm(prompt)
    fname.write_text(test_code, encoding='utf-8')
    return fname

def implement_feature(ticket, failing_output=None):
    # Build a code-only allowlist (exclude tests; tests are generated separately)
    allowlist = [p for p in ticket['area_allowlist'] if not p.startswith('tests/')]
    # If cli.py is allowed, allow __main__.py too (models often add module entrypoints)
    if 'src/your_package/cli.py' in allowlist and 'src/your_package/__main__.py' not in allowlist:
        allowlist.append('src/your_package/__main__.py')
    file_context = read_allowed_files(ticket, paths=allowlist)
    # Expand allowlist to include sanitized variants if needed (mostly for code paths)
    expanded = []
    for p in allowlist:
        if p.startswith('tests/') and '-' in p:
            expanded.append(p.replace('-', '_'))
    allowlist += [p for p in expanded if p not in allowlist]
    prompt = textwrap.dedent('''
    You are a senior software engineer. Implement the feature below by generating a patch in the unified diff format.

    Feature: {title}

    Description:
    {desc}

    Acceptance criteria:
    {criteria}

    Here are the current contents of the files you are allowed to modify:
    {file_context}

    Your task is to implement the feature. Do NOT modify any files under tests/ in this step; tests are handled separately.
    Output ONLY complete files using file blocks (no diffs, no prose, no extra text):
    ```file:relative/path/from/repo/root.py
    <entire file content here>
    ```
    Keep total changed lines under {max_lines}.
    Allowed paths: {allowlist}
    {failing}
    ''').format(
        title=ticket['title'],
        desc=ticket['description'],
        criteria=json.dumps(ticket['acceptance_tests'], indent=2),
        max_lines=ticket.get('max_changed_lines', MAX_CHANGED_LINES_DEFAULT),
        allowlist=allowlist,
        failing=('Previous failing output:\n' + failing_output) if failing_output else '',
        file_context=file_context or '(no files exist yet)'
    )
    patch_text = call_llm(prompt)
    apply_patches(patch_text, allowlist)

def append_changelog(ticket):
    path = REPO / 'CHANGELOG.md'
    ts = datetime.utcnow().strftime('%Y-%m-%d')
    entry = f"- {ts} {ticket['id']}: {ticket['title']}\n"
    if path.exists():
        path.write_text(path.read_text(encoding='utf-8') + entry, encoding='utf-8')
    else:
        path.write_text('# Changelog\n\n' + entry, encoding='utf-8')

def run_tests():
    return run_cmd(['pytest', '-q'], check=False)

def main():
    backlog = read_backlog(REPO / 'backlog' / 'features.yml')
    ticket = pick_next_ticket(backlog)
    if not ticket:
        print('No ready tickets.')
        return 0
    branch = f"feat/{ticket['id'].lower()}"
    git('checkout', '-B', branch)

    # 1) Generate tests
    test_file = write_tests(ticket)
    git('add', str(test_file))
    git('commit', '-m', f"test({ticket['id']}): add acceptance tests")

    # 2) Implement + retry loop
    attempt, failing_output = 0, None
    while attempt < MAX_RETRIES:
        attempt += 1
        try:
            implement_feature(ticket, failing_output)
        except Exception as e:
            # Capture error and retry with the failing output to guide the next attempt
            err = f"{type(e).__name__}: {e}"
            print('Patch application failed:', err)
            failing_output = (failing_output or '') + "\n\nPatch application failed:\n" + err
            continue
        git('add', '-A')
        git('commit', '-m', f"feat({ticket['id']}): {ticket['title']} (attempt {attempt})", allow_empty=True)
        res = run_tests()
        if res.returncode == 0:
            append_changelog(ticket)
            git('add', 'CHANGELOG.md')
            git('commit', '-m', f"docs({ticket['id']}): update changelog")
            from scripts.open_pr import ensure_pr
            pr_url = ensure_pr(ticket, branch)
            print(f"Opened PR: {pr_url}")
            return 0
        failing_output = res.stdout.decode() + "\n" + res.stderr.decode()
        print('Tests failing, retrying...')

    from scripts.open_pr import ensure_pr
    pr_url = ensure_pr(ticket, branch, draft=True, body_suffix="\n\n⚠️ Out of auto-fix retries. Needs review.")
    print(f"WIP PR opened: {pr_url}")
    return 1

if __name__ == '__main__':
    sys.exit(main())
