# Product-owned security claims

This Git tree is the authoritative specification source for the proposed claims listed in claim-registry.json. The factory reads an exact commit and derives a registry view; it does not maintain an independently editable registry copy. The claim is a proposed requirement, not evidence that its enforcement works. No covered occurrence or runtime acceptance is asserted.

The ARI claim preserves security, legitimate behavior and shared-boundary obligations from JER-13 contract v7. Version 2 moves the proposal beside product code and enumerates current implementation files. The prior missing proposed trust-loader file is not pretended to exist. New occurrences reuse the property identity; membership never closes a finding.

Contract and evaluator amendments must be approved by a separately configured trusted reviewer key, bound to the exact proposal, source and policy digest. The producer may propose but cannot self-approve, including through a reviewer alias using the same key. Revoked, expired, replayed or changed-source approvals are rejected. Keys and authority policy are provisioned outside patch-controlled inputs; signatures alone do not establish OS/repository isolation.

Verification handoffs copy all security/business/architecture predicates and checks, full claim/evaluator digests, context resources, permitted actions, budget and amendment route. A summary is explanatory context, not authority to weaken them. Missing positive behavior or a deny-all repair cannot satisfy the claim.

The factory implements the registry, signed-admission and handoff gates in its portable stage helpers. Real reviewer key provisioning and repository protection remain unverified. This PR does not add GitHub Actions, scheduling, CODEOWNERS, repository rules, transport repair, credentials or deployment.
