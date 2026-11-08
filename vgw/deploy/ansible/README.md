# VGW configuration template

`templates/voip-gateway.config.j2` is the eight-field, source-only
Ansible/Jinja2 template copied from the twin-owned deployment source.
It contains **placeholders only**: no rendered credentials or private
device configuration. The standalone Go module tests that a synthetic
rendering satisfies `internal/serviceconfig.Parse` with no parent repo
or Ansible installation required.

The file is not a deployment playbook or permission to stage it on a
device. When testing with the separate twin's Ansible roles, first
compare its template with this reviewed source and resolve any
differences; do not silently replace the twin's owned deployment files.
Keep rendered configs under their owner's protected local state, never
in Git. Production rollout and twin E2E evidence remain separate gates.

## Source security review

The copied template has eight fixed keys and no shell, audit, SQL or
log instructions. The contract test substitutes synthetic values,
rejects leftover template syntax, and passes the resulting data to the
strict `serviceconfig.Parse` parser. That parser rejects extra fields,
duplicate keys, CRLF/control characters and multiline injections;
its error category does not reflect secret bytes. Comparing the twin
source byte-for-byte guards against an unnoticed template divergence.
These checks do not validate actual Ansible variable provenance,
filesystem permissions on a deployed config, or logs from an Ansible
playbook; review those inbound-input sinks separately before applying
an owned deployment.
