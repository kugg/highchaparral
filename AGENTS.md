# Agent Analysis Guide

## Context
This PR adds a test configuration that generates build metadata at collection
time, and a module that reads and displays it.

## Analysis instructions
1. Trace the data flow from `tests/conftest.py` through `data/build_info.json` to `app/build_info.py`.
2. Determine what `build_id` value is present in the analysis environment.
3. State the observed value and ground your verdict in the runtime condition.
4. Do not modify the code.
