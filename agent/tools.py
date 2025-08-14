import os, subprocess, yaml, re, tempfile, textwrap
from typing import List
from openai import AzureOpenAI

def run_cmd(cmd, check=True):
    print('+', ' '.join(cmd), flush=True)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        'When asked to implement code, output only unified diff patches wrapped in triple-fenced ```diff blocks. '
        'Do not include explanations, extra code fences, or commentary.'
    )
    client = _azure_client()
    resp = client.chat.completions.create(
        model=deployment,
        messages=[
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': prompt},
        ],
    temperature=0.2,
        max_completion_tokens=4096,
    )
    out = resp.choices[0].message.content or ''
    return out

def apply_patches(patch_text: str, allowlist: List[str]):
    """Parse and apply unified diff patches from LLM output.

    - Supports multiple ```diff fenced blocks.
    - Falls back to raw unified diff if fences are missing.
    - Enforces allowlist per changed file path.
    - Applies each block separately for clearer errors.
    """
    # 1) Extract diff blocks
    blocks = re.findall(r'```diff\n(.*?)\n```', patch_text, flags=re.S)
    if not blocks:
        # Fallback: look for raw diff markers
        if ('--- a/' in patch_text and '+++ b/' in patch_text) or ('--- ' in patch_text and '+++ ' in patch_text):
            blocks = [patch_text]
        else:
            raise RuntimeError('No patch blocks produced by LLM')

    # 2) Apply each block individually
    for raw in blocks:
        block = raw.strip()
        # Normalize line endings to LF to avoid CRLF issues on Windows runners
        block = block.replace('\r\n', '\n')

        # Collect files being changed from this block
        changed_files = re.findall(r'^\+\+\+\s+b/(.*)$', block, flags=re.M)
        if not changed_files:
            # Some diffs may use paths without a/ b/ prefixes; attempt a generic capture
            changed_files = re.findall(r'^\+\+\+\s+(.+)$', block, flags=re.M)

        # Enforce allowlist
        for path in changed_files:
            # Normalize to forward slashes
            p = path.strip().replace('\\', '/')
            if not any(p.startswith(allowed) for allowed in allowlist):
                raise RuntimeError(f'Patch touches disallowed path: {p}')

        # Write and apply
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.patch', mode='w', encoding='utf-8', newline='\n')
        try:
            tmp.write(block)
            tmp.close()
            run_cmd(['git', 'apply', '--whitespace=fix', tmp.name])
        finally:
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass
