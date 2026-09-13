# Q0.10 cross-run fresh-observer reacquisition

This bounded public-safe experiment tests whether a completely fresh GitHub Actions workflow run can reconstruct and semantically verify prior public Actions evidence using only durable GitHub run metadata and artifacts.

It consumes the already-completed Q0.8 and Q0.9 public experiment evidence and does not introduce a model, inference call, secret, OIDC grant, paid runner, external actuator mutation, merge, release, or governance promotion.

The experiment is intentionally narrow: it tests durable reacquisition across workflow-run boundaries. It does not claim portfolio semantics, generalized orchestration, or private-state resumability.
