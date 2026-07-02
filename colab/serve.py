"""Serve a security LLM on a Colab GPU and print an OpenAI-compatible URL.

Run it on a Colab runtime via the Google Colab CLI (needs your Google login):

    pip install google-colab-cli          # or: pipx install google-colab-cli
    colab new --gpu T4                     # provision a free T4 runtime
    colab exec -f colab/serve.py           # run this script on it
    # ...watch the output for the trycloudflare URL, then paste into
    #    cyberhackmythos → model dropdown → Custom endpoint… → Base URL

Keep the runtime alive (`colab console` to attach; `colab stop` to end).
Paste  <printed-url>/v1  as Base URL, the MODEL below, and any api key.
"""

import re
import subprocess
import time

MODEL = "monotykamary/whiterabbitneo-v1.5a"  # security-tuned; swap for any Ollama tag


def sh(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=False)


def main() -> None:
    # 1) Ollama (OpenAI-compatible server on :11434)
    sh("curl -fsSL https://ollama.com/install.sh | sh")
    subprocess.Popen(["ollama", "serve"])
    time.sleep(5)
    sh(f"ollama pull {MODEL}")

    # 2) Public tunnel via cloudflared (no signup)
    sh("wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/"
       "cloudflared-linux-amd64 -O /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared")
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", "http://localhost:11434"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    url = None
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="")
        m = re.search(r"https://[-a-z0-9]+\.trycloudflare\.com", line)
        if m:
            url = m.group(0)
            break

    print("\n" + "=" * 64)
    print("Paste into cyberhackmythos → model dropdown → Custom endpoint…:")
    print("  Base URL :", (url or "<tunnel failed — rerun>") + "/v1")
    print("  Model    :", MODEL)
    print("  API key  : ollama")
    print("=" * 64)
    # Keep the process (and tunnel) alive.
    proc.wait()


if __name__ == "__main__":
    main()
