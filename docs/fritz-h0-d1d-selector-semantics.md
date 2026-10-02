# FRITZ H0-D1d linux_fs_start selector semantics

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1d narrows the exact open-source AVM MTD/TFFS files to the definition and consumers of
`linux_fs_start`. It emits function ownership, key-specific getter calls/assignments,
safe comparison classes, and public-name presence without publishing source lines or
arbitrary literals.

The result is still not permission to write the boot environment or flash hardware.
