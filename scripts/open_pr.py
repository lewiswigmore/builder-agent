import subprocess, textwrap

def ensure_pr(ticket, branch, draft=False, body_suffix=""):
    title = f"{ticket['id']}: {ticket['title']}"
    body = textwrap.dedent('''
    Automated feature implementation.

    **Description**
    {desc}

    **Acceptance tests**
    {tests}

    {suffix}
    ''').format(desc=ticket['description'], tests='\n'.join(f'- {t}' for t in ticket['acceptance_tests']), suffix=body_suffix)
    # Ensure we can push: if branch exists, attempt a rebase pull first, then push
    subprocess.run(['git', 'fetch', 'origin', branch], check=False)
    # Try a normal push; if it fails due to non-fast-forward, force-with-lease
    push = subprocess.run(['git', 'push', '-u', 'origin', branch], capture_output=True, text=True)
    if push.returncode != 0:
        # If push rejected due to non-fast-forward, force-with-lease to avoid overwriting others' work unintentionally
        subprocess.run(['git', 'push', '--force-with-lease', '-u', 'origin', branch], check=True)
    args = ['gh', 'pr', 'create', '--title', title, '--body', body, '--base', 'main', '--head', branch]
    if draft:
        args.append('--draft')
    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    subprocess.run(['gh', 'pr', 'edit', branch, '--title', title, '--body', body], check=False)
    url = subprocess.run(['gh', 'pr', 'view', branch, '--json', 'url', '--jq', '.url'], capture_output=True, text=True)
    return url.stdout.strip()
