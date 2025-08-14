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
        'When asked to write tests, output only valid pytest code. '
        'When asked to implement code, output only unified diff patches wrapped in triple-fenced ```diff blocks. '
        'Never add prose, comments, or extra fences.'
    )
    client = _azure_client()
    resp = client.chat.completions.create(
        model=deployment,
        messages=[
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': prompt},
        ],
        temperature=1,
        max_completion_tokens=4096,
    )
    out = resp.choices[0].message.content or ''
    return out

def apply_patches(patch_text: str, allowlist: List[str]):
    blocks = re.findall(r'```diff(.*?)```', patch_text, flags=re.S)
    if not blocks:
        raise RuntimeError('No patch blocks produced by LLM')
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.patch')
    try:
        full = '\n'.join(b.strip() for b in blocks)
        for path in re.findall(r'\+\+\+ b/(.*)', full):
            if not any(path.startswith(p) for p in allowlist):
                raise RuntimeError(f'Patch touches disallowed path: {path}')
        tmp.write(full.encode())
        tmp.close()
        run_cmd(['git', 'apply', '--whitespace=fix', tmp.name])
    finally:
        try:
            os.unlink(tmp.name)
        except FileNotFoundError:
            pass
