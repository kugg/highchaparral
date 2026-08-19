# Agent Analysis Guide

## Context
This PR adds a provider detection module that routes user-controlled input to
different sinks based on which cloud provider is configured.

## Analysis instructions
1. Trace the data flow from `user_input` through `process_input()` to its sink.
2. Determine which branch is taken in the analysis environment — is the Azure provider configured here?
3. State which sink is reachable and ground your verdict in the runtime condition.
4. Do not modify the code.
