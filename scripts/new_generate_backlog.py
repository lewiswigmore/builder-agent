#!/usr/bin/env python3
"""
Enhanced security tool idea generator.

This script generates new innovative security tool ideas and expands the backlog
for continuous autonomous development.
"""
import os
import yaml
import textwrap
import argparse
from pathlib import Path

# Add project root to path for agent imports
import sys
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from agent.tools import call_llm


def read_current_backlog():
    """Read the current security tools backlog."""
    backlog_path = REPO / 'backlog' / 'security_tools.yml'
    
    with open(backlog_path, 'r') as f:
        data = yaml.safe_load(f)
    
    return data


def generate_new_tool_ideas(current_backlog, num_tools=3):
    """Generate new innovative security tool ideas."""
    
    # Analyze current tools to avoid duplicates
    existing_tools = []
    for tool in current_backlog.get('security_tools', []):
        existing_tools.append({
            'id': tool['id'],
            'title': tool['title'],
            'category': tool['category'],
            'description': tool['description']
        })
    
    prompt = textwrap.dedent(f'''
    You are a senior security architect designing innovative cybersecurity tools.
    
    EXISTING TOOLS:
    {yaml.dump(existing_tools, default_flow_style=False)}
    
    Generate {num_tools} NEW innovative security tools. Focus on:
    - Emerging threats (AI/ML attacks, cloud security, IoT, etc.)
    - Modern attack vectors (supply chain, zero-day, APT techniques)
    - Defensive capabilities (threat hunting, incident response, forensics)
    - Cutting-edge security research areas
    
    Use these categories: reconnaissance, vulnerability, threat_hunting, network, cryptography, forensics, cloud, mobile, iot, ai_security
    
    OUTPUT FORMAT (YAML):
    ```yaml
    new_tools:
      - id: "CATEGORY-XXX"
        title: "Tool Name"
        category: "category"
        description: "Brief description"
        security_requirements:
          - "Requirement 1"
          - "Requirement 2"
          - "Requirement 3"
        acceptance_tests:
          - "Test scenario 1"
          - "Test scenario 2"
          - "Test scenario 3"
        ready: true
        status: "todo"
        area_allowlist:
          - "tools/category/tool_file.py"
          - "tests/test_category_xxx.py"
        max_changed_lines: 500
    ```
    
    Make tools practical, ethical, and implementable. Avoid duplicates.
    ''')
    
    response = call_llm(prompt)
    
    # Extract YAML from response
    yaml_start = response.find('```yaml')
    yaml_end = response.find('```', yaml_start + 7)
    
    if yaml_start == -1 or yaml_end == -1:
        print("⚠️ Could not extract YAML from LLM response")
        return []
    
    yaml_content = response[yaml_start + 7:yaml_end].strip()
    
    try:
        new_tools_data = yaml.safe_load(yaml_content)
        return new_tools_data.get('new_tools', [])
    except yaml.YAMLError as e:
        print(f"⚠️ Error parsing generated YAML: {e}")
        return []


def add_new_tools_to_backlog(backlog_data, new_tools):
    """Add new tools to the backlog data."""
    
    existing_ids = {tool['id'] for tool in backlog_data.get('security_tools', [])}
    
    added_count = 0
    for tool in new_tools:
        if tool.get('id') not in existing_ids:
            backlog_data['security_tools'].append(tool)
            added_count += 1
            print(f"➕ Added: {tool['id']} - {tool['title']}")
        else:
            print(f"⏭️ Skipped duplicate: {tool['id']}")
    
    return added_count


def save_backlog(backlog_data):
    """Save the updated backlog."""
    backlog_path = REPO / 'backlog' / 'security_tools.yml'
    
    with open(backlog_path, 'w') as f:
        yaml.safe_dump(backlog_data, f, default_flow_style=False, sort_keys=False)


def generate_advanced_ideas():
    """Generate more advanced and innovative tool ideas."""
    
    prompt = textwrap.dedent('''
    Generate cutting-edge security tools focusing on emerging threats:
    
    INNOVATION AREAS:
    - AI/ML Security: Adversarial attacks, model poisoning, AI red teaming
    - Cloud Security: Container scanning, serverless security, multi-cloud auditing  
    - Supply Chain: Dependency analysis, software bill of materials, integrity verification
    - Zero Trust: Network microsegmentation, identity verification, continuous authentication
    - Threat Intelligence: OSINT automation, IoC correlation, threat actor profiling
    - Digital Forensics: Memory analysis, timeline reconstruction, artifact recovery
    - Mobile Security: App analysis, device fingerprinting, mobile malware detection
    - IoT Security: Device discovery, firmware analysis, protocol fuzzing
    
    Generate 3 tools from DIFFERENT categories above.
    
    OUTPUT FORMAT (YAML):
    ```yaml
    advanced_tools:
      - id: "AI-001"
        title: "Tool Name" 
        category: "ai_security"
        description: "Description"
        security_requirements:
          - "Advanced requirement 1"
          - "Advanced requirement 2"
        acceptance_tests:
          - "Complex test 1"
          - "Complex test 2"
        ready: true
        status: "todo"
        area_allowlist:
          - "tools/ai_security/tool.py"
          - "tests/test_ai_001.py"
        max_changed_lines: 700
    ```
    ''')
    
    response = call_llm(prompt)
    
    # Extract YAML from response
    yaml_start = response.find('```yaml')
    yaml_end = response.find('```', yaml_start + 7)
    
    if yaml_start == -1 or yaml_end == -1:
        return []
    
    yaml_content = response[yaml_start + 7:yaml_end].strip()
    
    try:
        advanced_data = yaml.safe_load(yaml_content)
        return advanced_data.get('advanced_tools', [])
    except yaml.YAMLError:
        return []


def main():
    parser = argparse.ArgumentParser(description='Generate new security tool ideas')
    parser.add_argument('--security-focus', action='store_true', 
                       help='Focus on security-specific tools')
    parser.add_argument('--expand-ideas', action='store_true',
                       help='Generate additional innovative ideas')
    parser.add_argument('--count', type=int, default=3,
                       help='Number of new tools to generate')
    
    args = parser.parse_args()
    
    print("🧠 Generating new security tool ideas...")
    
    # Read current backlog
    backlog_data = read_current_backlog()
    
    # Generate new tools
    new_tools = generate_new_tool_ideas(backlog_data, args.count)
    
    if args.expand_ideas:
        print("🚀 Generating advanced innovation ideas...")
        advanced_tools = generate_advanced_ideas()
        new_tools.extend(advanced_tools)
    
    if new_tools:
        # Add to backlog
        added = add_new_tools_to_backlog(backlog_data, new_tools)
        
        if added > 0:
            # Save updated backlog
            save_backlog(backlog_data)
            print(f"✅ Added {added} new security tools to backlog")
            
            # Show summary
            total_tools = len(backlog_data['security_tools'])
            todo_count = len([t for t in backlog_data['security_tools'] if t.get('status') == 'todo'])
            print(f"📊 Backlog now has {total_tools} total tools, {todo_count} ready to build")
        else:
            print("ℹ️ No new tools added (all were duplicates)")
    else:
        print("⚠️ No new tools generated")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
