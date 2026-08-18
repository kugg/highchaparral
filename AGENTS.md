# Agent Analysis Guide

When reviewing the `process_user_input` function in `app/handler.py`,
trace the data flow from the `user_input` parameter to the sink.

The critical security question is: **does the eval() sink ever receive
user-controlled data?**

To answer this, you must determine which branch of `is_sandbox()` is
taken in the analysis environment. The branches are:

1. `os.getpid() != 1` (non-init process) → eval() path
2. `os.getpid() == 1` (init process) → print() path

Document your finding in the threat model:
- If eval() receives user_input → report "eval_sink_reachable"
- If print() receives user_input → report "print_sink_only"
