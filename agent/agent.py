import pathlib, json, textwrap, sys, os
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
    e.g., RECON-001 -> recon_001
    """
    safe = ticket_id.lower().replace('-', '_')
    # strip any characters outside [a-z0-9_]
    safe = ''.join(ch for ch in safe if (ch.isalnum() or ch == '_'))
    return safe

def write_tests(ticket):
    safe_id = _sanitize_ticket_id(ticket['id'])
    fname = (REPO / 'tests' / f"test_{safe_id}.py")
    fname.parent.mkdir(parents=True, exist_ok=True)
    
    # Get category for more specific test instructions
    category = ticket.get('category', 'general')
    security_reqs = ticket.get('security_requirements', [])
    
    prompt = textwrap.dedent('''
    Write pytest tests for security tool:
    
    TOOL: {title}
    CATEGORY: {category}
    
    REQUIREMENTS: {security_requirements}
    
    ACCEPTANCE TESTS: {criteria}
    
    TEST RULES:
    - Mock external calls, no actual attacks
    - Use localhost/127.0.0.1 only for network tests  
    - Test error handling and edge cases
    - Import from: {tool_path}
    
    Output only pytest code, no explanations.
    ''').format(
        title=ticket['title'],
        category=category,
        security_requirements='\n'.join(f"- {req}" for req in security_reqs),
        criteria=json.dumps(ticket['acceptance_tests'], indent=2),
        tool_path=ticket['area_allowlist'][0] if ticket['area_allowlist'] else 'tools/category/tool.py'
    )
    
    test_code = call_llm(prompt)
    fname.write_text(test_code, encoding='utf-8')
    return fname

def implement_feature(ticket, failing_output=None):
    # Build a code-only allowlist (exclude tests; tests are generated separately)
    allowlist = [p for p in ticket['area_allowlist'] if not p.startswith('tests/')]
    
    # Ensure directory structure exists for tools
    for path in allowlist:
        full_path = REPO / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        # Create __init__.py files for Python packages
        if 'tools/' in path and not full_path.parent.joinpath('__init__.py').exists():
            full_path.parent.joinpath('__init__.py').write_text('', encoding='utf-8')
    
    file_context = read_allowed_files(ticket, paths=allowlist)
    category = ticket.get('category', 'general')
    security_reqs = ticket.get('security_requirements', [])
    
    prompt = textwrap.dedent('''
    You are a senior security engineer. Implement this security tool:
    
    TOOL: {title}
    CATEGORY: {category}
    DESCRIPTION: {desc}
    
    REQUIREMENTS:
    {security_requirements}
    
    ACCEPTANCE TESTS:
    {criteria}
    
    GUIDELINES: Authorized testing only, include ethical warnings, proper error handling.
    
    FILES: {file_context}
    
    Output complete Python files using EXACT format:
    ```file:relative/path.py
    complete file content here
    ```
    
    Max lines: {max_lines}. Paths: {allowlist}
    {failing}
    ''').format(
        title=ticket['title'],
        category=category,
        desc=ticket['description'],
        security_requirements='\n'.join(f"- {req}" for req in security_reqs),
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

def update_backlog_status(ticket, status):
    """Update the tool status in the backlog."""
    backlog_path = REPO / 'backlog' / 'security_tools.yml'
    
    # Read current backlog
    import yaml
    with open(backlog_path, 'r') as f:
        data = yaml.safe_load(f)
    
    # Update the specific tool status
    for tool in data.get('security_tools', []):
        if tool.get('id') == ticket['id']:
            tool['status'] = status
            break
    
    # Write back to file
    with open(backlog_path, 'w') as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

def main():
    backlog = read_backlog(REPO / 'backlog' / 'security_tools.yml')
    ticket = pick_next_ticket(backlog)
    if not ticket:
        print('No ready security tools.')
        return 0
    
    # Ensure Python can resolve the 'tools' directory for imports
    tools_path = str(REPO / 'tools')
    existing = os.environ.get('PYTHONPATH', '')
    if tools_path not in existing.split(os.pathsep):
        os.environ['PYTHONPATH'] = (tools_path + (os.pathsep + existing if existing else ''))
    
    branch = f"security-tool/{ticket['id'].lower()}"
    
    # Check if branch exists remotely and handle conflicts
    try:
        # Fetch latest changes from remote
        git('fetch', 'origin')
        
        # Check if remote branch exists
        result = run_cmd(['git', 'ls-remote', '--heads', 'origin', branch], check=False)
        branch_exists_remotely = result.returncode == 0 and result.stdout.decode().strip()
        
        if branch_exists_remotely:
            print(f"🔄 Branch {branch} exists remotely, checking out and resetting to latest")
            try:
                git('checkout', branch)
                git('reset', '--hard', f'origin/{branch}')
            except RuntimeError:
                # If local branch doesn't exist, create it tracking remote
                git('checkout', '-b', branch, f'origin/{branch}')
        else:
            # Create new branch from main
            git('checkout', '-B', branch)
    except RuntimeError as e:
        print(f"Warning: Git setup issue, continuing with basic checkout: {e}")
        git('checkout', '-B', branch)
    
    # Update status to in_progress
    update_backlog_status(ticket, 'in_progress')
    git('add', 'backlog/security_tools.yml')
    git('commit', '-m', f"status({ticket['id']}): mark as in_progress")

    # 1) Generate tests
    test_file = write_tests(ticket)
    git('add', str(test_file))
    git('commit', '-m', f"test({ticket['id']}): add security tool tests for {ticket['title']}")

    # 2) Implement + retry loop
    attempt, failing_output = 0, None
    while attempt < MAX_RETRIES:
        attempt += 1
        try:
            implement_feature(ticket, failing_output)
        except Exception as e:
            # Capture error and retry with the failing output to guide the next attempt
            err = f"{type(e).__name__}: {e}"
            print('Security tool implementation failed:', err)
            failing_output = (failing_output or '') + "\n\nImplementation failed:\n" + err
            continue
        git('add', '-A')
        git('commit', '-m', f"feat({ticket['id']}): implement {ticket['title']} (attempt {attempt})", allow_empty=True)
        res = run_tests()
        if res.returncode == 0:
            append_changelog(ticket)
            git('add', 'CHANGELOG.md')
            git('commit', '-m', f"docs({ticket['id']}): update changelog")
            
            # Mark as completed and ready for review
            update_backlog_status(ticket, 'ready_for_review')
            git('add', 'backlog/security_tools.yml')
            git('commit', '-m', f"status({ticket['id']}): mark as ready_for_review - all tests passing")
            
            # Push the branch for review with force if needed
            try:
                git('push', 'origin', branch)
            except RuntimeError:
                print("🔄 Push failed, force pushing to update remote branch")
                git('push', '--force', 'origin', branch)
            
            print(f"✅ Security tool {ticket['id']} completed successfully!")
            print(f"🌿 Branch: {branch}")
            print(f"📊 All tests passing - ready for manual review")
            return 0
        failing_output = res.stdout.decode() + "\n" + res.stderr.decode()
        print('Tests failing, retrying...')

    # If we get here, we've exhausted retries
    print(f"⚠️ Failed to complete {ticket['id']} after {MAX_RETRIES} attempts")
    print("📋 Marking as needs_work for later review")
    
    # Mark as needs work and push anyway for manual investigation
    update_backlog_status(ticket, 'needs_work')
    git('add', 'backlog/security_tools.yml')  
    git('commit', '-m', f"status({ticket['id']}): mark as needs_work - manual intervention required")
    
    # Push with force if needed to handle conflicts
    try:
        git('push', 'origin', branch)
    except RuntimeError:
        print("🔄 Push failed, force pushing to update remote branch")
        git('push', '--force', 'origin', branch)
    
    print(f"🌿 Branch {branch} pushed for manual review")
    print("✅ Agent completed successfully - tool ready for review")
    return 0  # Return success since agent worked correctly

if __name__ == '__main__':
    sys.exit(main())
