# VGW component contracts

Claims and fences are defined once in claims.json. Developers and agents maintain
these contracts together as ordinary component code, following this repository's
normal contribution and code ownership policy. No separate security-team approval
is introduced by the catalog.

Keep intended behavior explicit, preserve legitimate callers, and update fences
when the architecture changes. Explain requirement changes in the PR. Test hard
controls; use guidance and review policies to share intention. A claim edit or a
source-review verdict alone is not evidence that an implementation satisfies it.
Keep run results and computed hashes in receipts, not this catalog.
