"""OpenAI-compatible LLM client (Viettel gateway) with sqlite response cache + usage accounting."""
from __future__ import annotations
import hashlib
import json
import sqlite3
import threading
import time
from openai import OpenAI
from .. import config

_lock = threading.Lock()
_db = sqlite3.connect(config.LLM_CACHE_DB, check_same_thread=False, timeout=120)
_db.execute("CREATE TABLE IF NOT EXISTS llm (k TEXT PRIMARY KEY, resp TEXT, ts REAL)")
_db.commit()
_client = None

USAGE: dict[str, dict] = {}   # model -> {calls, prompt, completion, cached, seconds}


def client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(base_url=config.LLM_BASE_URL, api_key=config.LLM_API_KEY, timeout=300, max_retries=1)
    return _client


def _acc(model, **kw):
    with _lock:
        u = USAGE.setdefault(model, {"calls": 0, "prompt": 0, "completion": 0, "cached": 0, "seconds": 0.0})
        for k, v in kw.items():
            u[k] += v


def reset_usage():
    USAGE.clear()


def chat(model: str, messages: list[dict], tools: list[dict] | None = None, max_tokens: int = 2048,
         temperature: float = 0.0, seed_tag: str = "") -> dict:
    """Returns {'content': str|None, 'tool_calls': [{'id','name','arguments'(dict)}], 'usage': {...}}"""
    # Qwen models are run in non-thinking mode (parity with Claude without extended thinking; latency)
    # All models run WITHOUT extended reasoning (same setting for Claude and Qwen; bounded latency/cost)
    extra = ({"chat_template_kwargs": {"enable_thinking": False}} if model.startswith("Qwen/")
             else {"reasoning_effort": "none"} if model.startswith("claude") else None)
    key = hashlib.sha256(json.dumps([model, messages, tools, max_tokens, temperature, seed_tag, extra], sort_keys=True,
                                    default=str).encode()).hexdigest()
    with _lock:
        row = _db.execute("SELECT resp FROM llm WHERE k=?", (key,)).fetchone()
    if row:
        r = json.loads(row[0])
        _acc(model, calls=1, cached=1, prompt=r["usage"].get("prompt", 0), completion=r["usage"].get("completion", 0))
        return r
    if config.OFFLINE:
        raise RuntimeError("LLM call not cached and VERA_OFFLINE=1")
    t0 = time.time()
    kw = dict(model=model, messages=messages, max_tokens=max_tokens, temperature=temperature)
    if tools:
        kw["tools"] = tools
    if extra:
        kw["extra_body"] = extra
    last = None
    for attempt in range(3):
        try:
            resp = client().chat.completions.create(**kw)
            break
        except Exception as e:  # gateway hiccups
            last = e
            time.sleep(3 * (attempt + 1))
    else:
        raise last
    msg = resp.choices[0].message
    tcs = []
    for tc in msg.tool_calls or []:
        try:
            args = json.loads(tc.function.arguments or "{}")
        except json.JSONDecodeError:
            args = {"_raw": tc.function.arguments}
        tcs.append({"id": tc.id, "name": tc.function.name, "arguments": args})
    content = msg.content
    if content and "</think>" in content:  # Qwen reasoning traces
        content = content.split("</think>", 1)[1].strip()
    usage = {"prompt": getattr(resp.usage, "prompt_tokens", 0) or 0, "completion": getattr(resp.usage, "completion_tokens", 0) or 0}
    r = {"content": content, "tool_calls": tcs, "usage": usage}
    dt = time.time() - t0
    _acc(model, calls=1, prompt=usage["prompt"], completion=usage["completion"], seconds=dt)
    with _lock:
        _db.execute("INSERT OR REPLACE INTO llm VALUES (?,?,?)", (key, json.dumps(r), time.time()))
        _db.commit()
    return r


def extract_json(text: str | None):
    """Best-effort JSON extraction from an LLM answer."""
    if not text:
        return None
    t = text.strip()
    if "```" in t:
        parts = t.split("```")
        for p in parts[1::2]:
            p = p.split("\n", 1)[1] if p.lstrip().startswith(("json", "JSON")) else p
            try:
                return json.loads(p)
            except json.JSONDecodeError:
                continue
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i, j = t.find(open_c), t.rfind(close_c)
        if i != -1 and j > i:
            try:
                return json.loads(t[i:j + 1])
            except json.JSONDecodeError:
                pass
    return None
