# scripts/generate_backlog.py
import argparse, re, sys, os, json, yaml, pathlib, datetime
from openai import AzureOpenAI

REPO = pathlib.Path(__file__).resolve().parents[1]
BACKLOG = REPO / "backlog" / "features.yml"

def azure_client():
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY")
    api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
    if not endpoint or not api_key:
        raise SystemExit("Missing AZURE_OPENAI_ENDPOINT or AZURE_OPENAI_API_KEY")
    return AzureOpenAI(api_version=api_version, azure_endpoint=endpoint, api_key=api_key)

def repo_snapshot(max_bytes=6000) -> str:
    """Return a compact context the model can use: tree + a few key files."""
    parts = []
    for p in sorted(REPO.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(REPO).as_posix()
        if any(rel.startswith(x) for x in [".git/", ".github/", ".venv/", ".pytest_cache/"]):
            continue
        if len("\n".join(parts)) > max_bytes:
            break
        parts.append(rel)
    tree = "\n".join(parts)
    def read_if(path):
        fp = REPO / path
        if fp.exists() and fp.is_file():
            try:
                txt = fp.read_text(encoding="utf-8")[:2000]
                return f"\n--- {path} ---\n{txt}\n"
            except:
                return ""
        return ""
    sample = read_if("README.md") + read_if("pyproject.toml") + read_if("requirements.txt") + read_if("src/your_package/cli.py")
    return f"FILES:\n{tree}\n{sample}"

def load_backlog():
    if BACKLOG.exists():
        return yaml.safe_load(BACKLOG.read_text(encoding="utf-8")) or {"features": []}
    BACKLOG.parent.mkdir(parents=True, exist_ok=True)
    return {"features": []}

def save_backlog(data):
    BACKLOG.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")

def normalise_title(t: str) -> str:
    return re.sub(r"\s+", " ", t.strip().lower())

def make_ids(n: int):
    today = datetime.datetime.utcnow().strftime("%Y%m%d")
    for i in range(1, n+1):
        yield f"FEAT-{today}-{i:03d}"

PROMPT_TEMPLATE = """You are a senior developer writing a tiny backlog for a very small Python project.

Project snapshot:
{snapshot}

Write {count} MICRO-features that are realistic, each safely completable in ≤150 changed lines INCLUDING tests and docs.
Rules:
- Keep each task laser-focused and independent.
- Each MUST include 2–4 clear acceptance tests (pytest style description, not code).
- Provide a tight allow-list of files to touch (src/your_package/* and tests/* only).
- Use British English spellings in text.
- Output STRICTLY as YAML that matches this schema:

features:
  - id: PLACEHOLDER
    title: "Short imperative title"
    description: "One-paragraph description"
    acceptance_tests:
      - "describe expected behaviour #1"
      - "..."
    ready: true
    status: todo
    area_allowlist:
      - "path/file1.py"
      - "tests/test_file1.py"
    max_changed_lines: 150
"""

def propose_features(k: int):
    client = azure_client()
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT")
    if not deployment:
        raise SystemExit("Missing AZURE_OPENAI_DEPLOYMENT")
    prompt = PROMPT_TEMPLATE.format(snapshot=repo_snapshot(), count=k)
    resp = client.chat.completions.create(
        model=deployment,
        messages=[{"role":"system","content":"Output valid YAML only. No prose."},
                  {"role":"user","content":prompt}],
        temperature=0.2,
        max_completion_tokens=1200,
    )
    text = resp.choices[0].message.content or ""
    try:
        data = yaml.safe_load(text)
        feats = data.get("features", [])
        # Guard: schema sanity
        cleaned = []
        for f in feats:
            if not all(k in f for k in ("title","description","acceptance_tests","area_allowlist")):
                continue
            f["ready"] = True
            f["status"] = "todo"
            f.setdefault("max_changed_lines", 150)
            cleaned.append(f)
        return cleaned
    except Exception as e:
        raise SystemExit(f"YAML parse failed: {e}\n---\n{text[:500]}")

def merge_features(existing, proposed, add_n: int):
    known_titles = {normalise_title(f["title"]) for f in existing["features"]}
    new_items = []
    for f in proposed:
        if normalise_title(f["title"]) in known_titles:
            continue
        new_items.append(f)
        if len(new_items) >= add_n:
            break
    # assign ids
    for id_, item in zip(make_ids(len(new_items)), new_items):
        item["id"] = id_
    existing["features"].extend(new_items)
    return new_items

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-ready", type=int, default=1, help="Ensure at least this many ready todo tickets exist")
    ap.add_argument("--make", type=int, default=3, help="How many proposals to request")
    args = ap.parse_args()

    backlog = load_backlog()
    ready_todos = [f for f in backlog["features"] if f.get("ready") and f.get("status") == "todo"]
    if len(ready_todos) >= args.min_ready:
        print(f"Backlog already has {len(ready_todos)} ready todo(s). Skipping generation.")
        return 0

    proposed = propose_features(args.make)
    added = merge_features(backlog, proposed, add_n=max(0, args.min_ready - len(ready_todos)))
    if not added:
        # If we didn’t meet min-ready, add at least one item
        added = merge_features(backlog, proposed, add_n=1)
    save_backlog(backlog)
    print(f"Added {len(added)} new feature(s): " + ", ".join(f['id'] for f in added))
    return 0

if __name__ == "__main__":
    sys.exit(main())
