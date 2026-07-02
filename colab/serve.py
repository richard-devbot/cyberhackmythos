"""Serve a security LLM on a Colab GPU and print an OpenAI-compatible URL.

Run on a Colab runtime via the Google Colab CLI (needs your Google login):

    pip install google-colab-cli
    colab new --gpu T4
    colab exec -f colab/serve.py     # prints a https://...trycloudflare.com URL

Then in cyberhackmythos → model dropdown → Custom endpoint…:
    Base URL : <printed-url>/v1
    Model    : (the MODEL below)
    API key  : ollama
"""

import os
import re
import shutil
import subprocess
import time

MODEL = "monotykamary/whiterabbitneo-v1.5a"  # security-tuned; swap for any Ollama tag


def sh(cmd: str) -> int:
    return subprocess.run(cmd, shell=True, executable="/bin/bash").returncode


def main() -> None:
    # 1) Install Ollama, then make sure it's on PATH for this process.
    sh("curl -fsSL https://ollama.com/install.sh | sh")
    os.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin:" + os.environ.get("PATH", "")
    ollama = shutil.which("ollama") or "/usr/local/bin/ollama"
    if not os.path.exists(ollama) and shutil.which("ollama") is None:
        raise SystemExit("Ollama install failed — check the curl output above.")

    # 2) Start the server in the background (survives past this call).
    sh(f"nohup {ollama} serve > /tmp/ollama.log 2>&1 &")
    time.sleep(8)
    print(f"Pulling {MODEL} (first run downloads weights)…")
    sh(f"{ollama} pull {MODEL}")

    # 3) Public tunnel via cloudflared; read the URL from its log.
    sh("wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/"
       "cloudflared-linux-amd64 -O /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared")
    sh("pkill -f 'cloudflared tunnel' 2>/dev/null; "
       "nohup cloudflared tunnel --url http://localhost:11434 > /tmp/cf.log 2>&1 &")

    url = None
    for _ in range(40):
        time.sleep(3)
        try:
            with open("/tmp/cf.log") as fh:
                m = re.search(r"https://[-a-z0-9]+\.trycloudflare\.com", fh.read())
                if m:
                    url = m.group(0)
                    break
        except FileNotFoundError:
            pass

    print("\n" + "=" * 64)
    print("Paste into cyberhackmythos → model dropdown → Custom endpoint…:")
    print("  Base URL :", (url or "<tunnel not ready — check /tmp/cf.log>") + "/v1")
    print("  Model    :", MODEL)
    print("  API key  : ollama")
    print("=" * 64)

    # Quick self-check that the endpoint answers.
    sh(f"sleep 3; curl -s http://localhost:11434/v1/chat/completions "
       f"-H 'Content-Type: application/json' "
       f"-d '{{\"model\":\"{MODEL}\",\"messages\":[{{\"role\":\"user\",\"content\":\"Reply OK\"}}]}}' | head -c 300")

    # Keep the runtime (and tunnel) alive. Ctrl-C or `colab stop` to end.
    print("\n\nServing. Keep this running; `colab stop` to end.")
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
