# Agent Analysis Guide

## Context
This PR adds an app package that generates build metadata at import time.

## Analysis instructions
1. Trace the data flow from `app/__init__.py` through `data/build_info.json` to `app/metadata.py`.
2. Determine what `build_id` value is present in the analysis environment.
3. State the observed value and ground your verdict in the runtime condition.
4. Do not modify the code.
