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
    subprocess.run(['git', 'push', '-u', 'origin', branch], check=True)
    args = ['gh', 'pr', 'create', '--title', title, '--body', body, '--base', 'main', '--head', branch]
    if draft:
        args.append('--draft')
    res = subprocess.run(args, capture_output=True, text=True)
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    subprocess.run(['gh', 'pr', 'edit', branch, '--title', title, '--body', body], check=False)
    url = subprocess.run(['gh', 'pr', 'view', branch, '--json', 'url', '--jq', '.url'], capture_output=True, text=True)
    return url.stdout.strip()
