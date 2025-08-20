#!/usr/bin/env python3
"""
Security Tool Branch Review Helper

This script helps you review all security tool branches and decide which ones to merge.
Provides an overview of all tools, their status, and test results.
"""
import subprocess
import yaml
import json
from pathlib import Path


def run_cmd(cmd, check=True):
    """Run a command and return result."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"❌ Command failed: {result.stderr}")
        return None
    return result


def get_security_branches():
    """Get all security tool branches."""
    result = run_cmd('git branch -r | grep "origin/security-tool/"', check=False)
    if not result or result.returncode != 0:
        return []
    
    branches = []
    for line in result.stdout.split('\n'):
        line = line.strip()
        if line.startswith('origin/security-tool/'):
            branch = line.replace('origin/', '')
            branches.append(branch)
    
    return branches


def get_branch_info(branch):
    """Get detailed information about a security tool branch."""
    # Switch to branch
    run_cmd(f'git checkout {branch}', check=False)
    
    # Get tool ID and details
    tool_id = branch.replace('security-tool/', '').upper()
    
    # Find tool files
    tool_files = []
    test_files = []
    
    for tool_dir in ['tools/recon', 'tools/vuln', 'tools/threat_hunt', 'tools/crypto', 'tools/network', 'tools/forensics', 'tools/cloud', 'tools/mobile', 'tools/iot', 'tools/ai_security']:
        if Path(tool_dir).exists():
            for py_file in Path(tool_dir).glob('*.py'):
                if py_file.name != '__init__.py':
                    tool_files.append(str(py_file))
    
    for test_file in Path('tests').glob('test_*.py'):
        test_files.append(str(test_file))
    
    # Run tests and get results
    test_result = run_cmd('python -m pytest tests/ -q --tb=no', check=False)
    test_status = "✅ PASS" if test_result and test_result.returncode == 0 else "❌ FAIL"
    
    # Get commit count
    commit_result = run_cmd(f'git rev-list --count {branch}', check=False)
    commit_count = commit_result.stdout.strip() if commit_result else "unknown"
    
    # Get last commit info
    last_commit = run_cmd('git log -1 --format="%h %s" HEAD', check=False)
    last_commit_info = last_commit.stdout.strip() if last_commit else "unknown"
    
    return {
        'branch': branch,
        'tool_id': tool_id,
        'tool_files': tool_files,
        'test_files': test_files,
        'test_status': test_status,
        'commit_count': commit_count,
        'last_commit': last_commit_info
    }


def get_backlog_status():
    """Get current backlog status."""
    backlog_path = Path('backlog/security_tools.yml')
    if not backlog_path.exists():
        return {}
    
    with open(backlog_path, 'r') as f:
        data = yaml.safe_load(f)
    
    status_counts = {}
    tools_by_status = {}
    
    for tool in data.get('security_tools', []):
        status = tool.get('status', 'unknown')
        status_counts[status] = status_counts.get(status, 0) + 1
        
        if status not in tools_by_status:
            tools_by_status[status] = []
        tools_by_status[status].append(tool)
    
    return {
        'status_counts': status_counts,
        'tools_by_status': tools_by_status,
        'total_tools': len(data.get('security_tools', []))
    }


def review_all_branches():
    """Review all security tool branches."""
    print("🔍 SECURITY TOOL BRANCH REVIEW")
    print("=" * 60)
    
    # Get current branch to restore later
    current_branch = run_cmd('git branch --show-current')
    original_branch = current_branch.stdout.strip() if current_branch else 'main'
    
    try:
        # Get all security branches
        branches = get_security_branches()
        
        if not branches:
            print("ℹ️ No security tool branches found")
            return
        
        print(f"📋 Found {len(branches)} security tool branches\n")
        
        # Review each branch
        branch_reviews = []
        for branch in branches:
            print(f"🔧 Reviewing {branch}...")
            info = get_branch_info(branch)
            branch_reviews.append(info)
        
        # Return to original branch
        run_cmd(f'git checkout {original_branch}')
        
        # Get backlog status
        backlog_info = get_backlog_status()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 REVIEW SUMMARY")
        print("=" * 60)
        
        print(f"\n📈 Backlog Overview:")
        print(f"  Total tools: {backlog_info['total_tools']}")
        for status, count in backlog_info['status_counts'].items():
            print(f"  {status}: {count}")
        
        print(f"\n🌿 Branch Review:")
        passing_branches = []
        failing_branches = []
        
        for review in branch_reviews:
            status_icon = "✅" if "PASS" in review['test_status'] else "❌"
            print(f"  {status_icon} {review['branch']}")
            print(f"     Tests: {review['test_status']}")
            print(f"     Files: {len(review['tool_files'])} tools, {len(review['test_files'])} tests")
            print(f"     Commits: {review['commit_count']}")
            print(f"     Last: {review['last_commit']}")
            print()
            
            if "PASS" in review['test_status']:
                passing_branches.append(review['branch'])
            else:
                failing_branches.append(review['branch'])
        
        print("🎯 RECOMMENDATIONS:")
        if passing_branches:
            print(f"✅ READY TO MERGE ({len(passing_branches)} branches):")
            for branch in passing_branches:
                print(f"   git checkout {branch} && git merge main && git checkout main && git merge {branch}")
        
        if failing_branches:
            print(f"⚠️ NEEDS WORK ({len(failing_branches)} branches):")
            for branch in failing_branches:
                print(f"   {branch} - fix tests before merging")
        
        print(f"\n🧹 CLEANUP COMMANDS:")
        print("# Delete merged branches:")
        for branch in passing_branches:
            print(f"git branch -d {branch} && git push origin --delete {branch}")
    
    finally:
        # Ensure we're back on original branch
        run_cmd(f'git checkout {original_branch}', check=False)


def main():
    """Main function."""
    try:
        review_all_branches()
    except Exception as e:
        print(f"❌ Error during review: {e}")
        # Try to get back to main
        run_cmd('git checkout main', check=False)
        return 1
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
