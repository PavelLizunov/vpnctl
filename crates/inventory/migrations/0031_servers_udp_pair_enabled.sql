-- naive↔HY2 UDP pairing — per-server operator opt-in (UX-3). When ON, the
-- subscription render stamps THIS node's naive AND hysteria2 share-links
-- with a shared `pair=<server id>` query param, so a client can carry UDP
-- (which naive can't) over the HY2 co-located on the SAME node. Pairing is
-- single-server only by construction — the tag is this server's id, unique
-- per node, so it can never join two nodes. Additive; default 0/off for
-- every existing server (backward-compatible: no node is paired until the
-- operator opts in from the server-detail page).
ALTER TABLE servers ADD COLUMN udp_pair_enabled INTEGER NOT NULL DEFAULT 0;
