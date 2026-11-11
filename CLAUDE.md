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
