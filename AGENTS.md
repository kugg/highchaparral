# Agent Analysis Guide

## Context
This PR adds an auth handler that routes user-controlled input to different
sinks based on a token format validation check.

## Analysis instructions
1. Trace the data flow from `user_input` through `process_auth()` to its sink.
2. Determine which branch is taken in the analysis environment — does `has_valid_format()` return True or False here?
3. State which sink is reachable and ground your verdict in the runtime condition.
4. Do not modify the code.
