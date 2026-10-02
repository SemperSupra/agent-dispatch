# FRITZ E2-D10 static protocol recovery

Authority: `SemperSupra/fritzbox-automation-private#72`.

E2-R9 established a stable control transaction shape without publishing payload bytes:

- request: 8-byte send + 260-byte send;
- response: one 260-byte read;
- pre/post `status` digests are stable;
- `start` differs in the first 8-byte request chunk and in the response.

D10 asks a narrower static question: does the exact shipped `svctl` binary expose
fixed verbs, imports, and callsite-adjacent fixed sizes consistent with the R9 shape,
and does the exact AVM OSP archive contain a source surface for `svctl` /
`supervisor`?

The reducer persists only fixed-token counts, ELF/import metadata, fixed-size
adjacency summaries, hashes/sizes, and fixed-token OSP path coverage. It does not
persist raw firmware, binaries, disassembly, arbitrary strings, source snippets, or
wire payloads.

A positive fixed-size adjacency is only a candidate structural relationship, not
data-flow proof. A source-token miss in OSP is only a coverage result and does not
imply the proprietary implementation is absent from the shipped firmware.
