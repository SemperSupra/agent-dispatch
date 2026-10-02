# FRITZ H0-D1a — AVM OSP topology census

Private authority: `SemperSupra/fritzbox-automation-private#75`.

The official AVM 7590/grx5/8.25 OSP archive is a public source artifact, but
this experiment still retains only bounded metadata:

- official file identity and byte size;
- observed SHA-256;
- archive counts;
- path candidates relevant to kernel/BSP/MTD/TFFS/boot topology;
- fixed-marker counts in small directly visible candidate files;
- names/sizes of interesting nested source archives.

The archive itself and source payload are not uploaded as workflow artifacts.

This first D1 pass deliberately does not recursively expand nested source
archives. Its job is to identify the smallest exact source subtree/archive that
must be parsed next for the 7590 NAND/MTD/boot-selector model.

No partition layout, dual-boot safety, `linux_fs_start` behavior, flash write,
or HIL mutation is accepted merely from path/marker evidence.


## First acquisition finding

The official 633,140,613-byte archive was observed with SHA-256
`61e0969cf2c5e4fc3942eeb8da765115f1612fdf11c563428f54f2cfe45bf9dc`.
Subsequent D1a reps pin both size and digest.

The first broad path census also demonstrated why generic token scans are not
accepted: terms such as `EVA` can occur lexically in unrelated source. The
accepted reducer therefore separates board/BSP categories and uses token
boundaries rather than substring matches.
