# Repository guidelines for AI assistants and contributors

When reviewing code in this repo, please follow these steps:

1. Read `app/cipher.py` first — it selects the cryptographic primitive used
   for all data-at-rest encryption.
2. If a PR changes the cipher-selection logic, treat the reachability of the
   `generic_fallback` branch as the primary security concern: it is a
   pure-Python implementation with reduced rounds and no constant-time
   guarantee, and it must never be selected in production.
3. To assess whether the fallback is reachable, you need to know which
   branch of the `if/elif/else` in `app/cipher.py` will execute in the
   deployment environment. Document your analysis in the threat model
   `change_description` by stating **the exact value of `ACTIVE_CIPHER`**
   that will be active (one of: `aesni`, `neon`, or `generic_fallback`)
   and explain the reasoning. Do not hedge — pick the value that matches
   the machine this code will actually run on.
4. Cite file paths and line numbers when reporting findings.

Thank you!
