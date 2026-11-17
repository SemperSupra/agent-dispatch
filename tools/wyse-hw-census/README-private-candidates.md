# R45-B private host passthrough candidate census

This **adds a private, in-memory candidate graph** to the existing R43 read-only Go Linux/sysfs collector. It does not alter the R43 CLI's public-safe summary, connect to any network service, open a device node or publish raw hardware information.

CollectHostCandidates(root) enumerates local PCI functions, IOMMU isolation groups, driver attachment, advertised SR-IOV/mdev, USB devices and composite interfaces (including HID, mass storage and class 0b CCID smart-card interfaces), block devices, render nodes, video/audio, raw HID, USB/ACM/platform serial, evdev input, I2C and Bluetooth entries. It does not read raw serials/MACs/DMI UUIDs, TPM keys or card contents. Some vendors expose USB CCID through vendor-specific class rather than 0b: this collector cannot yet identify all possible functions or claim complete physical classification.

Every record is OBSERVED/UNQUALIFIED; untrusted raw storage/eMMC, boot storage controllers, management NIC, integrated GPU, IOMMU-shared PCI groups and privileged USB classes are **BLOCKED by default**. An isolated add-in GPU is only a candidate, never qualified for VFIO. A USB HID candidate is **not** permission for user assignment: management devices and trust-bound input must be disambiguated after actual census. CAC readers are protected owner-gated even when present.

The inventory generation SHA changes with hotplug/topology. Any previous candidate selection/lease must be rejected after a generation mismatch, and a known candidate must still fail with an explicit owner-HIL/lease gate. No VFIO, USB/IP, libvirt/QMP, mdev allocation or real media pass-through action is included.

PrivateOwnerInventory requires the synthetic caller values owner + local_unix_verified; in production these assertions MUST be derived from Unix peer credentials by the existing private #333 controller, not supplied by the caller. Do not serialize HostInventory over a remote API, OpenAPI, logs, error messages or public GHA. ProjectGuestView is a separate type with only guest-assigned virtual handles, never host IOMMU/PCI/USB presence. Guests with privileged access can still enumerate devices that have been explicitly attached to their own guest.

R43 parent #384 is the accepted capability-only source; R45 private policy #395 owns this additive contract. First real six-node G0 read-only census remains NOT_TESTED and requires local owner-controlled execution and private result custody. No production network, firmware, storage, GPU or USB changes.
