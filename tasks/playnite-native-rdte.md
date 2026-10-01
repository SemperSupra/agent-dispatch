# Playnite native RDTE advancement

## Objective

Advance the approved public Playnite extensions target by **one bounded native-lifecycle RDTE rep**.

The work must stay aligned with Playnite's own development and distribution mechanisms:

- use the pinned Playnite runtime declared by the target repository;
- use the Toolbox shipped with that exact runtime;
- use Toolbox-generated plugin templates as compatibility oracles when creating test fixtures;
- build through the supported Playnite SDK/toolchain;
- package with `Toolbox.exe pack`;
- install the resulting `.pext` through Playnite's own extension installation lifecycle;
- use an isolated `--userdatadir`;
- run only on standard/free public GitHub-hosted runners;
- produce a machine-readable public-safe receipt.

## Allowed work

Within the approved public target repository, changes may be limited to:

- `.github/workflows/*playnite*rdte*.yml`
- `.github/workflows/*playnite*probe*.yml`
- `tooling/rdte/**`
- public RDTE documentation directly describing those files.

The actor may:
- inspect Playnite upstream source/documentation to resolve native behavior;
- add or refine deterministic runtime/package/install probes;
- add synthetic fixture generation that contains no private/user data;
- repair the harness when evidence shows a harness failure;
- open or update one pull request carrying the bounded change.

## Constraints

- Do not publish or reconstruct private SemperSupra plugin implementation.
- Do not access or request private repositories, private branches, user configuration, user library data, credentials, cookies, tokens, or provider sessions.
- Do not require any game/provider login.
- Do not hand-author Playnite database internals as the primary test path.
- Do not copy loose DLLs into the runtime as a substitute for native `.pext` installation.
- Do not introduce Windows App Foundry or another package manager.
- Do not create a custom Playnite installer/updater.
- Do not use private GitHub Actions minutes, paid/larger runners, self-hosted runners, or secrets.
- Do not merge or publish a release.
- Do not broaden workflow permissions beyond `contents: read`.
- Keep third-party GitHub Actions pinned to immutable commit SHAs.
- Treat failures as evidence; distinguish environment, harness, build, package, install, and oracle failures.

## Preferred progression

Advance only the highest currently-ready step:

1. pinned Playnite runtime materializes and hash verifies;
2. Toolbox from that runtime is present/callable;
3. isolated Playnite user-data initialization/shutdown works;
4. Toolbox-generated GenericPlugin builds;
5. Toolbox packs one `.pext`;
6. Playnite installs the package through its native install path;
7. restart/load smoke succeeds;
8. deterministic synthetic library seeding through supported SDK surfaces;
9. one representative plugin-behavior oracle.

Do not skip a failed prerequisite by replacing it with a non-native shortcut.

## Result contract

Return one pull request or an update to the existing bounded RDTE pull request.

In the pull request description or comment, record:

1. exact Playnite version and archive SHA-256;
2. runner label/image provenance;
3. source revision tested;
4. highest lifecycle step reached;
5. machine-readable receipt/artifact reference;
6. any failure classification;
7. the next highest READY bounded action.

Stop after one evidence-bearing advancement.
