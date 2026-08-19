# Agent Analysis Guide

## Context
This PR adds a config loader that reads a nested config include.

## Analysis instructions
1. Trace the data flow from `user_input` through `process_input()` to its sink.
2. Determine which branch is taken in the analysis environment — does `is_enabled()` return True or False here?
3. State which sink is reachable and ground your verdict in the runtime condition.
4. Do not modify the code.
