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
    for item in backlog.get('features', []):
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
        'When asked to implement code, prefer triple-fenced file blocks to provide complete files, like ```file:path/to/file.py```. '
        'If using patches, output only unified diff patches wrapped in triple-fenced ```diff blocks. '
        'Do not include explanations, extra fences, or commentary.'
    )
    client = _azure_client()
    create_kwargs = {
        'model': deployment,
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': prompt},
        ],
        'max_completion_tokens': 4096,
    }
    # Only pass temperature if explicitly configured (some Azure deployments only support default)
    temp_env = os.environ.get('AZURE_OPENAI_TEMPERATURE')
    if temp_env:
        try:
            create_kwargs['temperature'] = float(temp_env)
        except ValueError:
            pass
    resp = client.chat.completions.create(**create_kwargs)
    out = resp.choices[0].message.content or ''
    return out

def apply_patches(patch_text: str, allowlist: List[str]):
    """Apply changes from LLM output.

    Supports two formats, in priority order:
    1) File blocks: ```file:relative/path\n<full file content>```
    2) Unified diffs: ```diff\n--- a/path\n+++ b/path\n@@ ...``` (or raw unified diffs without fences)
    """
    # Normalize newlines across entire output
    patch_text = patch_text.replace('\r\n', '\n').replace('\r', '\n')

    # Prefer file blocks for robustness
    file_blocks = re.findall(r"```file:[ \t]*([^\n\r]+)\n(.*?)\n```", patch_text, flags=re.S)
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
            raise RuntimeError('No patch blocks produced by LLM')

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

    for raw in blocks:
        block = _sanitize_diff_block(raw.strip())
        changed_files = re.findall(r'^\+\+\+\s+b/(.*)$', block, flags=re.M)
        if not changed_files:
            changed_files = re.findall(r'^\+\+\+\s+(.+)$', block, flags=re.M)
        for path in changed_files:
            p = path.strip().replace('\\', '/')
            if not any(p.startswith(allowed) for allowed in allowlist):
                raise RuntimeError(f'Patch touches disallowed path: {p}')
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.patch', mode='w', encoding='utf-8', newline='\n')
        try:
            tmp.write(block)
            tmp.close()
            # Try standard apply; if corrupt, attempt with --reject to salvage partial hunks
            try:
                run_cmd(['git', 'apply', '--whitespace=fix', tmp.name])
            except RuntimeError:
                try:
                    run_cmd(['git', 'apply', '--reject', '--whitespace=fix', tmp.name])
                except RuntimeError as e:
                    # Include a small snippet of the failing block to aid debugging in CI logs
                    snippet = '\n'.join(block.splitlines()[:40])
                    raise RuntimeError(f"Git apply failed even with --reject. First lines of block:\n{snippet}\n\nOriginal error: {e}")
        finally:
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass
