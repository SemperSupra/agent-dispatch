# FRITZ H0-D1l selector arm skeleton

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1k normalized the selector condition over `{0,1}`, but both ternary arms were
opaque expressions with three identifiers each. D1l recovers only a sanitized
syntax skeleton for those arms:

- safe identifier names;
- roles such as function-like call, array base, member base/name, macro-like, or
  plain identifier;
- operator-shape classes;
- independent identifier occurrence counts in the selected partition/device-tree
  sources.

D1l does not publish source snippets or arbitrary literals and does not accept a
selector-to-destination mapping. The skeleton exists only to identify the next
mechanically resolvable naming relation. Modified HIL remains blocked.
