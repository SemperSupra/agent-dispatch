# macOS sealed-bundle repair qualification

This bounded child exists only to force a fresh public qualification matrix for the macOS install/repair seal fix.

Invariant under test:

- all files inside `SupraChat.app`, including the uninstall helper, are materialized before outer-bundle signing;
- `install.sh` is copy-only with respect to the signed app bundle;
- first install must pass `codesign --verify --strict`;
- same-build repair/reinstall must pass the same verification;
- installed CLI diagnostics must remain runnable;
- uninstall uses the pre-sealed helper and removes app + CLI shims.

No product-scope expansion is authorized by this child.
