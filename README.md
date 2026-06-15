---
title: OpenMythos
emoji: 🛡️
colorFrom: gray
colorTo: indigo
sdk: gradio
sdk_version: 6.18.0
python_version: '3.13'
app_file: app.py
pinned: true
short_description: An Open Source Cyber Security Agent
license: apache-2.0
tags:
  - gradio
  - build-small-hackathon
  - backyard-ai
  - track:backyard
  - sponsor:modal
  - achievement:offbrand
  - achievement:welltuned
  - achievement:fieldnotes
  - achievement:offgrid
---

# OpenMythos 🌌

**Paste your codebase. Our AI security agent audits the repository** a multi-level vulnerability analysis, a visual dependency risk path, a declared threat level then generates an instant, verifiable hotfix patch before threat actors can exploit it.

Built during the **Hugging Face Small Gradio Hackathon** OpenMythos democratizes cutting-edge security auditing. It bridges an immersive retro terminal interface with the elite agentic reasoning and long-context preservation architecture of a fine-tuned dense model.

> ⚠️ **Proactive Defense.** This platform is engineered for defensive security intelligence. It aims to discover flaws, memory leaks, security configurations, and input bugs instantly, empowering software engineering teams to deploy hotfixes long before a threat vector is weaponized.

---

## ▶️ See it in action

- **Demo Video:** https://www.youtube.com/watch?v=EQyHawWfyZ0
- **Social Post:** [X](https://x.com/kingnish24/status/2066602499356889493) [Linkedin](https://www.linkedin.com/feed/update/urn:li:activity:7472370083663765504) [Reddit](https://www.reddit.com/r/LocalLLaMA/comments/1u6qw5b/we_trained_a_cybersecurityfocused_mythos_like_llm/)
- **Blog Post:** https://huggingface.co/blog/KingNish/OpenMythos

---

## 🏕️ Hackathon Categories

| Category | Why OpenMythos Qualifies |
|:---------|:-------------------------|
| **Main Track: Backyard AI** | Solves a real, specific problem for real people: software teams need instant security auditing. The person is every developer who ships code and wants to catch vulnerabilities before attackers do. |
| **🔌 Off the Grid** | **100% Local & Privacy-First.** The entire pipeline runs with zero cloud API dependencies just a local model endpoint. Your code never leaves your machine. |
| **🎯 Well-Tuned** | Built on a **Qwen3.6-27B** base fine-tuned via SFT on cybersecurity dataset. The fine-tuned model: https://huggingface.co/build-small-hackathon/OpenMythos |
| **🎨 Off-Brand** | Fully custom terminal-inspired UI all pushing far past the default Gradio look. |

### Bonus Quests

| Badge | Status | Notes |
|:------|:-------|:------|
| 🔌 Off the Grid | ✅ **Earned** | Local-first by design |
| 🎯 Well-Tuned | ✅ **Earned** | SFT on cybersecurity data; model to be published |
| 🎨 Off-Brand | ✅ **Earned** | Custom CSS, SVG, terminal theme |
| 📓 Field Notes |  ✅ **Earned** | Blog post: https://huggingface.co/blog/KingNish/OpenMythos |

## Why it's worth a look

- 🔌 **100% Local & Privacy-First.** Designed as a fully open-source alternative to proprietary security intelligence layers (like Claude's Mythos model). It can be run entirely locally, requiring zero internet connectivity or external dependencies to operate.

## How it works

A multi-stage engineering pipeline built around aggregated, industry-standard security sources:

| Stage | Role | Source Data / Methodology |
|:-----:|------|---------------------------|
| **1** | **Data Prep & Aggregation** | Incident reports, GitHub Advisory, VulnHub, and papers. Rigorously trained on BigVul-Filtered and Arvix-Filtered sets. |
| **2** | **Initial Fine-Tuning (SFT)** | Supervised Fine-Tuning on cybersecurity tasks. Qwen3.6-27B Base (Up to 32K+ token context window). |

The entire pipeline leverages highly specialized weights to ensure an elite vulnerability discovery rate. No massive API dependencies anywhere: a clever chain of targeted engineering delivers the whole security suite.

## 🤝 Project Contributors

Developed with ❤️ during the **Hugging Face Small Gradio Hackathon** by:

- **KingNish** – [HuggingFace Profile](https://huggingface.co/KingNish)
- **Himanshu** – [HuggingFace Profile](https://huggingface.co/himanshu17HF)

*Built for the Build Small Hackathon. Model: [OpenMythos](https://huggingface.co/build-small-hackathon/OpenMythos) · Dataset: [CVE Vulnerabilities Detailed](https://huggingface.co/datasets/build-small-hackathon/CVE_Vulnerailities_Detailed) · [ArXiv cs.CR Filtered](https://huggingface.co/datasets/himanshu17HF/ArvixImport-Filtered-Final) · Space: [OpenMythos](https://huggingface.co/spaces/build-small-hackathon/OpenMythos)*