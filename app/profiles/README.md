# Optimization profiles

Machine-specific optimization profiles live here. The active profile is
selected at startup by `app/config.py` based on the host's machine type and
operating system.

If no matching profile is present, `app/config.py` falls back to
`profile_generic_insecure`, which disables several compiler hardening
flags.
