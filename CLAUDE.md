# Token-efficiency rules

- Never read whole files or tool output over ~200 lines. Use Grep with
  narrow patterns, `head`/`tail`, `wc -l`, or Read with offset/limit.
- Decompiled code (jadx/apktool/ghidra output), logs, pcaps and HCI
  captures live under `work/` (gitignored). Search them; never dump them.
  Pipe through `grep -m 20`, `rg -c`, or `tshark -Y <filter> -c` first.
- Run noisy commands with output redirected to a file, then inspect a
  summary of that file.
- Don't spawn subagents unless asked.
- Answer in concise prose. No restating the question, no option surveys;
  give one recommendation and the reason.
- Before multi-step work, state the plan in <=5 lines and wait if it will
  take more than ~10 tool calls.
- Write findings to `docs/findings.md` as short bullets (UUIDs, endpoints,
  command formats) so later sessions don't re-derive them.
- Ask before downloading large files or running anything long.

## Secrets
- Real values live outside the repo in ~/.config/open-sock/ (mode 700). Never write values into tracked files, docs or commit messages. work/ is gitignored and must never be committed.
- env: holds EUFY_AES_KEY and EUFY_ACCOUNT_ID. Load for one command in Bash with: env $(cat ~/.config/open-sock/env) python3 scripts/<script>.py. In Fish: env (cat ~/.config/open-sock/env) python3 scripts/<script>.py
- eufy_creds.txt: Eufy account login, used only by the Frida login scripts under work/. The server does not need it.
- git-credentials: Forgejo token, read by git itself through the credential helper. The GitHub and Codeberg mirrors are push mirrors configured in Forgejo, so no token for them is needed locally.
- Do not bypass the pre-commit hook with --no-verify.
