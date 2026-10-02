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
