import os, subprocess, yaml, re, tempfile, textwrap, pathlib
from typing import List
from openai import AzureOpenAI

REPO = pathlib.Path(__file__).resolve().parents[1]

def run_cmd(cmd, check=True):
    print('+', ' '.join(cmd), flush=True)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=str(REPO))
    if check and res.returncode != 0:
        raise RuntimeError(res.stdout.decode() + '\n' + res.stderr.decode())
    return res

def git(*args, allow_empty=False):
    cmd = ['git'] + list(args)
    if allow_empty:
        cmd += ['--allow-empty']
    return run_cmd(cmd)

def read_backlog(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def pick_next_ticket(backlog):
    # Support both old 'features' and new 'security_tools' format
    items = backlog.get('security_tools', []) or backlog.get('features', [])
    for item in items:
        if item.get('ready') and item.get('status') == 'todo':
            return item
    return None

def _azure_client():
    endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
    api_key = os.environ.get('AZURE_OPENAI_API_KEY')
    api_version = os.environ.get('AZURE_OPENAI_API_VERSION', '2024-12-01-preview')
    if not endpoint or not api_key:
        raise RuntimeError('Missing AZURE_OPENAI_ENDPOINT or AZURE_OPENAI_API_KEY')
    return AzureOpenAI(api_version=api_version, azure_endpoint=endpoint, api_key=api_key)

def call_llm(prompt: str) -> str:
    deployment = os.environ.get('AZURE_OPENAI_DEPLOYMENT')
    if not deployment:
        raise RuntimeError('Missing AZURE_OPENAI_DEPLOYMENT env/variable')

    system = (
        'You are a precise coding agent. Respond with only the requested artefact. '
        'When asked to write tests, output only valid pytest code in a single file. '
        'When asked to implement code, output ONLY triple-fenced file blocks with complete files, like ```file:path/to/file.py```. '
        'Do not include explanations, diffs, or extra fences, only file blocks for changed files.'
    )
    client = _azure_client()
    
    create_kwargs = {
        'model': deployment,
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': prompt},
        ],
    }
    # Only pass temperature if explicitly configured
    temp_env = os.environ.get('AZURE_OPENAI_TEMPERATURE')
    if temp_env:
        try:
            create_kwargs['temperature'] = float(temp_env)
        except ValueError:
            pass
    
    resp = client.chat.completions.create(**create_kwargs)
    out = resp.choices[0].message.content or ''
    
    # Debug logging for empty responses
    if not out.strip():
        print(f"WARNING: Empty LLM response for deployment: {deployment}")
        print(f"Finish reason: {resp.choices[0].finish_reason}")
    
    return out

def apply_patches(patch_text: str, allowlist: List[str]):
    """Apply changes from LLM output.

    Supports two formats, in priority order:
    1) File blocks: ```file:relative/path\n<full file content>```
    2) Unified diffs: ```diff\n--- a/path\n+++ b/path\n@@ ...``` (or raw unified diffs without fences)
    """
    
    # Handle empty response gracefully
    if not patch_text or not patch_text.strip():
        # Create a minimal implementation as fallback
        code_allowlist = [p for p in allowlist if not p.startswith('tests/')]
        if code_allowlist:
            print("WARNING: Empty LLM response, creating minimal implementation")
            for p in code_allowlist:
                abs_path = (REPO / p).resolve()
                os.makedirs(abs_path.parent, exist_ok=True)
                
                # Create minimal Python file with placeholder
                minimal_content = '''"""
Minimal implementation placeholder
This tool needs manual completion
"""

def main():
    """Main function - implement tool functionality here"""
    print("Tool implementation needed")
    pass

if __name__ == "__main__":
    main()
'''
                with open(abs_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(minimal_content)
            return
        else:
            raise RuntimeError('No patch blocks produced by LLM and no code files to create fallback')
    
    # Normalize newlines across entire output
    patch_text = patch_text.replace('\r\n', '\n').replace('\r', '\n')

    # Try all possible file block patterns
    patterns = [
        # Original strict format
        r"```file:[ \t]*([^\n\r]+)\n(.*?)\n```",
        # Flexible format with language hint
        r"```(?:python|py)?[ \t]*\n[ \t]*(?:#[ \t]*)?file:[ \t]*([^\n\r]+)\n(.*?)\n```",
        # Simple python code blocks that might contain file content
        r"```python\n(.*?)\n```",
        r"```py\n(.*?)\n```",
        r"```\n(.*?)\n```"
    ]
    
    for pattern in patterns[:2]:  # Try file-specific patterns first
        file_blocks = re.findall(pattern, patch_text, flags=re.S | re.I)
        if file_blocks:
            for rel_path, content in file_blocks:
                p = rel_path.strip().replace('\\', '/')
                if not any(p.startswith(allowed) for allowed in allowlist):
                    raise RuntimeError(f'Patch touches disallowed path: {p}')
                # Ensure directories exist
                abs_path = (REPO / p).resolve()
                os.makedirs(abs_path.parent, exist_ok=True)
                # Normalize newlines to LF
                normalized = content.replace('\r\n', '\n')
                with open(abs_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(normalized)
            return

    # Tolerant file block parsing: any fenced code block whose first non-empty line is 'file: path'
    tolerant_blocks = re.findall(r"```[a-zA-Z0-9_-]*\n(.*?)\n```", patch_text, flags=re.S)
    extracted_any = False
    for blk in tolerant_blocks:
        # Skip empty blocks
        inner = blk.replace('\r\n', '\n').strip('\n')
        if not inner.strip():
            continue
        lines = inner.split('\n')
        # Find a 'file: path' marker in the first few lines
        header_idx = -1
        for i in range(min(5, len(lines))):
            m = re.match(r"\s*(?:#\s*)?file:\s*([^\n\r]+)\s*$", lines[i], flags=re.I)
            if m:
                header_idx = i
                rel_path = m.group(1).strip()
                content = '\n'.join(lines[i+1:])
                p = rel_path.replace('\\', '/')
                if not any(p.startswith(allowed) for allowed in allowlist):
                    raise RuntimeError(f'Patch touches disallowed path: {p}')
                abs_path = (REPO / p).resolve()
                os.makedirs(abs_path.parent, exist_ok=True)
                with open(abs_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(content)
                extracted_any = True
                break
        # If no header found, try if the entire block should go to a single allowed file (heuristic)
    if extracted_any:
        return

    # Heuristic fallback: if exactly one code file is allowed to change, and we see any fenced code block,
    # assume it is the full content for that file.
    code_allowlist = [p for p in allowlist if not p.startswith('tests/')]
    if len(code_allowlist) == 1:
        # Try generic code block patterns
        for pattern in patterns[2:]:  # Generic code block patterns
            blocks = re.findall(pattern, patch_text, flags=re.S)
            if blocks:
                p = code_allowlist[0]
                abs_path = (REPO / p).resolve()
                os.makedirs(abs_path.parent, exist_ok=True)
                # Use the first/largest code block as the file content
                content = max(blocks, key=len) if len(blocks) > 1 else blocks[0]
                # Clean up any file: markers at the start
                lines = content.split('\n')
                if lines and re.match(r'\s*(?:#\s*)?file:\s*', lines[0], re.I):
                    content = '\n'.join(lines[1:])
                content = content.replace('\r\n', '\n').strip('\n')
                with open(abs_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(content)
                return

    # Unfenced 'file: path' format anywhere in the text
    m = re.search(r"(?ims)^\s*file:\s*([^\n\r]+)\s*[\r\n]+(.*)$", patch_text)
    if m:
        rel_path = m.group(1).strip()
        content = m.group(2)
        p = rel_path.replace('\\', '/')
        if not any(p.startswith(allowed) for allowed in allowlist):
            raise RuntimeError(f'Patch touches disallowed path: {p}')
        abs_path = (REPO / p).resolve()
        os.makedirs(abs_path.parent, exist_ok=True)
        with open(abs_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)
        return

    # Otherwise, handle unified diffs
    # Capture diff blocks in fences (diff or patch, optional whitespace)
    blocks = re.findall(r'```\s*(?:diff|patch)[^\n]*\n(.*?)\n```', patch_text, flags=re.S)
    if not blocks:
        # Fallback: strip any code fences and look for raw diff markers
        if '```' in patch_text:
            cleaned = '\n'.join(line for line in patch_text.splitlines() if not line.strip().startswith('```'))
        else:
            cleaned = patch_text
        if ('--- a/' in cleaned and '+++ b/' in cleaned) or ('--- ' in cleaned and '+++ ' in cleaned):
            blocks = [cleaned]
        else:
            # Enhanced error message with debug info
            debug_preview = patch_text[:1000] + ('...' if len(patch_text) > 1000 else '')
            debug_info = (
                f"Response length: {len(patch_text)}\n"
                f"Contains backticks: {'```' in patch_text}\n"
                f"Contains 'file:': {'file:' in patch_text.lower()}\n"
                f"Response preview:\n{debug_preview}"
            )
            raise RuntimeError(f'No patch blocks produced by LLM. Debug info:\n{debug_info}')

    def _sanitize_diff_block(text: str) -> str:
        # Remove any stray code fence lines
        lines = [ln for ln in text.split('\n') if not ln.strip().startswith('```')]
        # Find first real diff header and slice from there
        start_idx = 0
        header_patterns = (re.compile(r'^diff\s+--git\s+'), re.compile(r'^---\s+'),)
        for i, ln in enumerate(lines):
            if any(pat.match(ln) for pat in header_patterns):
                start_idx = i
                break
        cleaned = '\n'.join(lines[start_idx:]).strip()
        return cleaned

    def _split_per_file_diff(block: str) -> List[str]:
        lines = block.split('\n')
        chunks = []
        cur = []
        for ln in lines:
            # A new file section starts at a '--- ' line or a 'diff --git' line
            if ln.startswith('diff --git') or (ln.startswith('--- ') and cur):
                if cur:
                    chunks.append('\n'.join(cur).strip() + '\n')
                    cur = []
            cur.append(ln)
        if cur:
            chunks.append('\n'.join(cur).strip() + '\n')
        return chunks

    def _clean_spurious_lines(chunk: str) -> str:
        # Drop stray fences, ensure modifications happen only within hunks
        out = []
        in_hunk = False
        for ln in chunk.split('\n'):
            if ln.strip().startswith('```'):
                continue
            if ln.startswith('@@'):
                in_hunk = True
                out.append(ln)
                continue
            if ln.startswith('diff --git') or ln.startswith('index ') or ln.startswith('--- ') or ln.startswith('+++ '):
                in_hunk = False
                out.append(ln)
                continue
            if ln.startswith('+') or ln.startswith('-'):
                if not in_hunk:
                    # Skip stray +/- lines outside hunks (likely formatting artefacts)
                    continue
                out.append(ln)
                continue
            # context line or blank
            out.append(ln)
        cleaned = '\n'.join(out).strip() + '\n'
        return cleaned

    for raw in blocks:
        block = _sanitize_diff_block(raw.strip())
        for file_chunk in _split_per_file_diff(block):
            cleaned = _clean_spurious_lines(file_chunk)
            # Determine target path
            m = re.search(r'^\+\+\+\s+b/(.*)$', cleaned, flags=re.M) or re.search(r'^\+\+\+\s+(.+)$', cleaned, flags=re.M)
            target = (m.group(1).strip() if m else '')
            p = target.replace('\\', '/')
            if p and not any(p.startswith(allowed) for allowed in allowlist):
                print(f"Skipping patch for disallowed path: {p}")
                continue
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.patch', mode='w', encoding='utf-8', newline='\n')
            try:
                tmp.write(cleaned)
                tmp.close()
                # Try standard apply; if corrupt, attempt with --reject to salvage partial hunks
                try:
                    run_cmd(['git', 'apply', '--whitespace=fix', tmp.name])
                except RuntimeError:
                    try:
                        run_cmd(['git', 'apply', '--reject', '--whitespace=fix', tmp.name])
                    except RuntimeError as e:
                        snippet = '\n'.join(cleaned.splitlines()[:60])
                        raise RuntimeError(f"Git apply failed even with --reject. First lines of block:\n{snippet}\n\nOriginal error: {e}")
            finally:
                try:
                    os.unlink(tmp.name)
                except FileNotFoundError:
                    pass
