import os
import subprocess
import yaml

def run_command(command, ignore_errors=False):
    """
    Runs a shell command, prints its output, and returns the subprocess result object.
    If ignore_errors is False, it will raise an exception on failure.
    """
    try:
        print(f"Executing: {command}")
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            shell=True
        )
        output = result.stdout.strip()
        if output:
            print(output)
        return result
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip()
        print(f"Error running command: {command}\n{stderr_output}")
        if not ignore_errors:
            raise
        return e

def get_remote_branches():
    """Fetches all remote branches and returns a list of security tool branches."""
    print("Fetching all remote branches...")
    run_command("git fetch --all --prune")
    result = run_command("git branch -r")
    output = result.stdout.strip()
    if not output:
        return []
    # Return full remote branch names like 'origin/security-tool/recon-001'
    branches = [
        b.strip() for b in output.split('\n') 
        if 'origin/security-tool/' in b and 'HEAD' not in b
    ]
    return branches

def update_backlog_status(tool_id, status):
    """Updates the status for a given tool_id in the backlog YAML file."""
    backlog_file = 'backlog/security_tools.yml'
    if not os.path.exists(backlog_file):
        print(f"Backlog file not found: {backlog_file}")
        return False

    try:
        with open(backlog_file, 'r') as f:
            backlog = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error reading backlog file: {e}")
        return False

    tool_found = False
    for tool in backlog.get('security_tools', []):
        if tool.get('id') == tool_id:
            tool['status'] = status
            tool_found = True
            break
    
    if tool_found:
        with open(backlog_file, 'w') as f:
            yaml.dump(backlog, f, default_flow_style=False, sort_keys=False)
        print(f"Updated {tool_id} status to '{status}' in {backlog_file}")
        return True
    else:
        print(f"Tool ID {tool_id} not found in backlog.")
        return False

def main():
    """Main function to orchestrate the review of all security tool branches."""
    # Start from a clean main branch
    run_command("git checkout main")
    run_command("git reset --hard origin/main")
    run_command("git pull origin main")

    remote_branches = get_remote_branches()
    if not remote_branches:
        print("No security tool branches found to review.")
        return

    print(f"Found security tool branches: {', '.join(remote_branches)}")

    for remote_branch in remote_branches:
        local_branch_name = remote_branch.split('/')[-1]
        tool_id_from_branch = local_branch_name.upper().replace('-', '_')
        tool_id_yaml = local_branch_name.upper().replace('_', '-')

        print(f"\n--- Reviewing Branch: {local_branch_name} ---")

        # Ensure a clean state before checking out the new branch
        run_command("git checkout main")
        run_command("git reset --hard origin/main")
        run_command(f"git branch -D {local_branch_name}", ignore_errors=True)
        
        # Create a fresh local branch from the remote
        run_command(f"git checkout -b {local_branch_name} {remote_branch}")

        # Run tests
        test_file = f"tests/test_{tool_id_from_branch.lower()}.py"
        if not os.path.exists(test_file):
            print(f"Test file not found: {test_file}. Skipping branch.")
            continue

        test_result = run_command(f"pytest {test_file}", ignore_errors=True)
        
        # pytest exit codes: 0 = all tests passed, 1 = tests failed, 5 = no tests found
        # A run with only skipped tests also returns 0.
        tests_passed = test_result.returncode == 0

        if tests_passed:
            print(f"Tests PASSED for {tool_id_yaml}.")
            run_command("git checkout main")
            run_command("git pull origin main")
            run_command(f'git merge --no-ff {local_branch_name} -m "Merge feature branch {local_branch_name}"')
            
            if update_backlog_status(tool_id_yaml, 'completed'):
                run_command("git add backlog/security_tools.yml")
                # Check for changes before committing
                if run_command("git diff --staged --quiet", ignore_errors=True).returncode != 0:
                    run_command(f"git commit -m 'Update backlog for {tool_id_yaml} to completed'")
            
            run_command("git push origin main")
            # The remote branch name includes 'origin/', which we need to remove for the delete command
            remote_branch_ref = remote_branch.replace('origin/', '')
            run_command(f"git push origin --delete {remote_branch_ref}")
            print(f"Successfully merged and cleaned up branch {local_branch_name}.")
        else:
            print(f"Tests FAILED for {tool_id_yaml}.")
            if update_backlog_status(tool_id_yaml, 'needs_work'):
                run_command("git add backlog/security_tools.yml")
                
                # Check if there are changes to commit before attempting to commit
                commit_check_result = run_command("git diff --staged --quiet", ignore_errors=True)
                if commit_check_result.returncode != 0:
                    run_command(f"git commit -m \"Auto-update backlog: {tool_id_yaml} needs work\"")
                    # Use force-with-lease to safely update the remote branch
                    push_result = run_command(f"git push --force-with-lease origin {local_branch_name}", ignore_errors=True)
                    if push_result.returncode == 0:
                        print(f"Pushed 'needs_work' status to branch {local_branch_name}.")
                    else:
                        print(f"Failed to push status to branch {local_branch_name}. It may be out of sync.")
                else:
                    print("No changes to commit for backlog status (it was already 'needs_work').")

    # Final cleanup
    run_command("git checkout main")
    print("\n--- Review complete ---")

if __name__ == "__main__":
    main()
