# Private contract loader v1

Open `.agent/transport/{{CORRELATION}}.json` in the already-authorized target repository.

Treat that transport record only as a locator. Follow its `dispatch_ref` to the authoritative private delegation record, then follow that record's `objective_ref` and execute exactly that private task.

Rules:

- do not infer or expand authority beyond the private delegation/task records;
- do not copy private repository names, private task content, source URLs, artifact identities, provider metadata, or result details into public repositories;
- obey the private task's egress, validator, attempt, and completion policies;
- do not weaken validation or classification controls to obtain a passing result;
- produce the durable result in the target repository as required by the private task;
- if the private locator/dispatch/task record is missing or malformed, stop without improvising.
