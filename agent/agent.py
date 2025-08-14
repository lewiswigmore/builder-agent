import pathlib, json, textwrap, sys
from datetime import datetime
from agent.tools import read_backlog, pick_next_ticket, git, run_cmd, call_llm, apply_patches
from agent.policies import MAX_RETRIES, MAX_CHANGED_LINES_DEFAULT

REPO = pathlib.Path(__file__).resolve().parents[1]

def write_tests(ticket):
    fname = (REPO / 'tests' / f"test_{ticket['id'].lower()}.py")
    fname.parent.mkdir(parents=True, exist_ok=True)
    prompt = textwrap.dedent('''
    Write pytest tests for this feature, minimal and focused.
    Acceptance criteria:
    {criteria}
    Project layout: src/your_package/
    Only write Python code for pytest in one file. No prose.
    ''').format(criteria=json.dumps(ticket['acceptance_tests'], indent=2))
    test_code = call_llm(prompt)
    fname.write_text(test_code, encoding='utf-8')
    return fname

def implement_feature(ticket, failing_output=None):
    prompt = textwrap.dedent('''
    Implement the feature below by editing only allow-listed files.

    Feature: {title}

    Description:
    {desc}

    Acceptance criteria:
    {criteria}

    Only suggest diffs as unified patches in fenced blocks:
    ```diff
    --- a/path.py
    +++ b/path.py
    @@
    - old
    + new
    ```
    Keep total changed lines under {max_lines}.
    Allowed paths: {allowlist}
    {failing}
    ''').format(
        title=ticket['title'],
        desc=ticket['description'],
        criteria=json.dumps(ticket['acceptance_tests'], indent=2),
        max_lines=ticket.get('max_changed_lines', MAX_CHANGED_LINES_DEFAULT),
        allowlist=ticket['area_allowlist'],
        failing=('Previous failing output:\n' + failing_output) if failing_output else ''
    )
    patch_text = call_llm(prompt)
    apply_patches(patch_text, ticket['area_allowlist'])

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
        implement_feature(ticket, failing_output)
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
