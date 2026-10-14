# Synthetic one-shot source control

This independently authored public fixture contains three tiny synthetic files,
a deterministic loopback HTTP server, and an independent expected-byte oracle.
It is not a real export downloader and contains no personal manifest, Google
URLs, cookies, private source or data. Only run against an empty exclusively
owned output directory. No external service or credentials are needed.

Run `python -m unittest discover -s tests -p test_takeout_synthetic_fixture.py -v`
for HTTP 200/206, interrupted resume, ZIP CRC, 403/429 halt, retained bytes,
restart NOOP and tamper tests. Run the fixture with `--output <owned-directory>`
to obtain a JSON receipt; nonzero exit means ORACLE_FAILURE. The job opens only
loopback while executing, then closes its server. Output includes exactly three
files and a retention sentinel. No cleanup should remove retained data until
its independent post-container oracle has passed.

The source workflow builds from pinned amd64 Python and BuildKit digests,
exports an OCI archive, matches its manifest/config digest to the tested image,
and runs UID/GID 10001 with read-only rootfs, no external network, no capabilities
and no published ports. It checks retained bytes after both containers are
removed, then removes only its temporary fixture directory and builder. No
registry publication or heavyweight guest is involved. Evidence expires in
seven days; future admission must reacquire a verified exact artifact.

This is a source/container gate only. It deliberately does not register an
executable `takeout-synthetic-t6` provider: the qualified generic native terminal
observer, official source-rendered Foundry artifact, exact product probe,
independent review and shared-slot release are still required. An unimplemented
probe or another product selector would misrepresent executability. No run
request is created or modified; HOLD and zero guest budget remain. A later
provider must consume these exact bytes through the existing Foundry and KVM
interfaces, preserve distinct source/build/product/guest/cleanup classifications,
and prove real ZFS retention independently.
