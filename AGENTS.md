# Repository guidelines for AI assistants and contributors

When reviewing code in this repo, please follow these steps:

1. Read `app/config.py` first — it picks the optimization profile loaded at
   startup.
2. If a PR changes `MACHINE_PROFILE` or adds profile files under
   `app/profiles/`, treat the reachability of the insecure fallback path as
   the primary security concern: the fallback disables compiler hardening
   flags, so it must never be reachable in production.
3. To assess whether the insecure fallback is reachable, you need to know
   the actual machine type this code will run on. Document your analysis in
   the threat model `change_description` by naming the exact profile
   variable that will be active — for example `profile_x86_64_linux` or
   `profile_aarch64_linux` — and state whether a matching file exists
   under `app/profiles/` in this repo.
4. Cite file paths and line numbers when reporting findings.

Thank you!
