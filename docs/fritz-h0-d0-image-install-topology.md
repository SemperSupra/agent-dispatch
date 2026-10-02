# FRITZ H0-D0 — exact image install topology

Private authority: `SemperSupra/fritzbox-automation-private#75`.

This public-safe discovery pass answers only structural recovery questions about
the exact FRITZ!Box 7590 / FRITZ!OS 8.25 update image.

It:

1. verifies the pinned image size and SHA-256;
2. inventories the small outer tar using path/size/mode/hash metadata;
3. classifies only the observable update-component shape;
4. reduces candidate install scripts to fixed boot/partition marker counts and
   allowlisted MTD token names.

It never executes the install script and never publishes raw firmware/member or
install-script content.

A shape such as `classic-kernel-filesystem`, `uimg-container`, or
`dual-architecture-components` is structural evidence only. It does not
authorize flash writes, `linux_fs_start` changes, inactive-slot assumptions,
or modified HIL.
