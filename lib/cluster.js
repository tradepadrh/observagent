// CLUSTER MAP — who is connected to whom around one token. Read-only, from public data.
// Links between holders come from three on-chain facts:
//   FUND   a wallet sent ETH to a holder before it bought (shared funder = likely same operator)
//   BLOCK  three or more wallets bought in the same block (bundle-style buying)
//   SEND   tokens moved directly between holders, or from the creator to a holder
// Wallets joined by any of these land in one cluster; the map reports each cluster's share of supply.
// Heuristic: a shared funder can also be an exchange or a bridge, so known contracts are never treated as funders.

const lc = (s) => String(s || "").toLowerCase();
const ZERO = "0x0000000000000000000000000000000000000000";
const DEAD = "0x000000000000000000000000000000000000dead";
const BURNS = new Set([ZERO, DEAD, "0x0000000000000000000000000000000000000001"]);
const INFRA_NAME = /BondingCurve|Pool|Router|Vault|Locker|Manager|Factory|Airlock|Hook|Pair|Swap|Uniswap|Sushi|Permit2|Multicall/i;

function createCluster({ env, rpc, threat }) {
  const BS = (env("BLOCKSCOUT_API") || env("EXPLORER_URL") || "https://robinhoodchain.blockscout.com").replace(/\/(token|address)\/.*$/, "").replace(/\/$/, "");
  const CFG = { holders: 36, transferPages: 8, conc: 6, ttl: 10 * 60e3 };
  const cache = new Map(), inflight = new Map(), funderCache = new Map(), codeCache = new Map();

  async function bs(path) {
    const ac = new AbortController(), t = setTimeout(() => ac.abort(), 10000);
    try {
      const r = await fetch(BS + path, { signal: ac.signal, headers: { accept: "application/json", "user-agent": "Mozilla/5.0 (compatible; ObservAgent/1.0; +https://observagent.tech)" } });
      if (r.status === 429) { await new Promise((z) => setTimeout(z, 800)); return bs(path); }
      if (!r.ok) throw new Error("explorer HTTP " + r.status);
      return await r.json();
    } finally { clearTimeout(t); }
  }
  async function pool(items, n, fn) {
    const out = new Array(items.length); let i = 0;
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; try { out[k] = await fn(items[k]); } catch (_) { out[k] = null; } } }));
    return out;
  }
  async function isWallet(a) { // EOA, including EIP-7702 delegated wallets
    if (codeCache.has(a)) return codeCache.get(a);
    let w = true; try { const c = await rpc("eth_getCode", [a, "latest"]); w = !c || c === "0x" || /^0xef0100[0-9a-f]{40}$/i.test(c); } catch (_) {}
    codeCache.set(a, w); if (codeCache.size > 8000) codeCache.clear(); return w;
  }
  // first ETH that reached this wallet from another wallet (newest-first page; the oldest entry wins)
  async function funderOf(a) {
    if (funderCache.has(a)) return funderCache.get(a);
    let f = null;
    try {
      const d = await bs(`/api/v2/addresses/${a}/transactions?filter=to`);
      const ins = (d.items || []).filter((t) => t.from && lc(t.to && t.to.hash) === a && BigInt(t.value || "0") > 0n && !(t.from.is_contract));
      const first = ins[ins.length - 1];
      if (first) f = { from: lc(first.from.hash), eth: Number(BigInt(first.value) / 10n ** 12n) / 1e6, tx: first.hash, t: first.timestamp, name: first.from.name || null };
    } catch (_) {}
    funderCache.set(a, f); if (funderCache.size > 20000) funderCache.clear(); return f;
  }

  async function build(token) {
    const [info, hol] = await Promise.all([bs(`/api/v2/tokens/${token}`), bs(`/api/v2/tokens/${token}/holders`)]);
    const dec = +(info.decimals || 18), supply = BigInt(info.total_supply || "0");
    const share = (v) => (supply > 0n ? Number((BigInt(v) * 1000000n) / supply) / 1e6 : 0);
    const sym = info.symbol || "?";
    // creator
    let creator = null;
    const sc = threat.cached && threat.cached(token);
    if (sc && sc.metrics && sc.metrics.deployer) creator = lc(sc.metrics.deployer);
    if (!creator) { try { const acct = await bs(`/api/v2/addresses/${token}`); const txh = acct.creation_transaction_hash || acct.creation_tx_hash; if (txh) { const tx = await bs(`/api/v2/transactions/${txh}`); creator = lc(tx.from && tx.from.hash); } } catch (_) {} }

    // transfers (newest first → reverse to chronological)
    const transfers = []; let next = null;
    for (let i = 0; i < CFG.transferPages; i++) {
      const q = next ? "?" + new URLSearchParams(next).toString() : "";
      let d; try { d = await bs(`/api/v2/tokens/${token}/transfers${q}`); } catch (_) { break; }
      for (const t of d.items || []) transfers.push({ from: lc(t.from.hash), to: lc(t.to.hash), fc: !!t.from.is_contract, tc: !!t.to.is_contract, fname: t.from.name || "", tname: t.to.name || "", v: BigInt((t.total && t.total.value) || "0"), blk: +t.block_number, tx: t.transaction_hash, t: t.timestamp });
      next = d.next_page_params; if (!next) break;
    }
    transfers.reverse();
    const fullHistory = !next;

    // classify addresses
    const infra = new Set([token, ...BURNS]);
    for (const h of hol.items || []) if (h.address && h.address.is_contract && INFRA_NAME.test(h.address.name || "")) infra.add(lc(h.address.hash));
    for (const t of transfers) { if (t.fc && INFRA_NAME.test(t.fname)) infra.add(t.from); if (t.tc && INFRA_NAME.test(t.tname)) infra.add(t.to); }
    const holders = [];
    for (const h of hol.items || []) {
      const a = lc(h.address.hash), v = BigInt(h.value || "0");
      if (BURNS.has(a)) { holders.push({ a, kind: "burn", v }); continue; }
      if (infra.has(a)) { holders.push({ a, kind: "infra", v, name: h.address.name || "contract" }); continue; }
      holders.push({ a, kind: h.address.is_contract ? "maybe" : "wallet", v });
    }
    await pool(holders.filter((h) => h.kind === "maybe"), CFG.conc, async (h) => { h.kind = (await isWallet(h.a)) ? "wallet" : "infra"; if (h.kind === "infra") infra.add(h.a); });
    // contracts that only appear in transfers (routers, curves): anything a buy comes "from" and is a contract
    for (const t of transfers) { if (t.fc) infra.add(t.from); if (t.tc && !holders.some((h) => h.a === t.to)) infra.add(t.to); }

    const wallets = holders.filter((h) => h.kind === "wallet").sort((a, b) => (b.v > a.v ? 1 : -1)).slice(0, CFG.holders);
    const W = new Map(wallets.map((h) => [h.a, h]));

    // same-block buyers (bought from infra; ≥3 distinct buyers in one block)
    const byBlock = new Map();
    for (const t of transfers) if (infra.has(t.from) && !infra.has(t.to) && !BURNS.has(t.to)) { if (!byBlock.has(t.blk)) byBlock.set(t.blk, new Set()); byBlock.get(t.blk).add(t.to); }
    const bursts = [...byBlock.entries()].filter(([, s]) => s.size >= 3).sort((a, b) => b[1].size - a[1].size).slice(0, 6);
    // ghosts: burst buyers that no longer hold (already exited)
    const bought = new Map(), sold = new Map();
    for (const t of transfers) { if (!infra.has(t.to)) bought.set(t.to, (bought.get(t.to) || 0n) + t.v); if (!infra.has(t.from)) sold.set(t.from, (sold.get(t.from) || 0n) + t.v); }
    const ghosts = new Map();
    const stillHolding = new Set(holders.map((h) => h.a));
    for (const [, s] of bursts) for (const a of s) if (!stillHolding.has(a) && ghosts.size < 40) ghosts.set(a, { a, kind: "exited", v: 0n, bought: bought.get(a) || 0n });

    // funders
    const fundTargets = [...wallets.map((h) => h.a), ...(creator && !W.has(creator) ? [creator] : [])].slice(0, CFG.holders + 1);
    const funds = await pool(fundTargets, CFG.conc, funderOf);
    const funderOfMap = new Map(); fundTargets.forEach((a, i) => { if (funds[i]) funderOfMap.set(a, funds[i]); });

    // ---------- graph ----------
    const nodes = new Map(), edges = [];
    const node = (id, o) => { if (!nodes.has(id)) nodes.set(id, { id, ...o }); return nodes.get(id); };
    node(token, { kind: "token", label: "$" + sym, pct: 1 });
    if (creator) node(creator, { kind: "creator", label: "CREATOR", pct: share((holders.find((h) => h.a === creator) || { v: 0n }).v) });
    for (const h of holders) {
      if (h.kind === "wallet" && !W.has(h.a)) continue;
      const n = node(h.a, { kind: h.a === creator ? "creator" : h.kind, label: h.kind === "infra" ? (h.name || "CONTRACT").replace(/([a-z])([A-Z])/g, "$1 $2").toUpperCase().slice(0, 22) : h.kind === "burn" ? "BURN" : null, pct: share(h.v) });
      n.pct = share(h.v);
      edges.push({ s: token, t: h.a, kind: "hold" });
    }
    for (const g of ghosts.values()) { node(g.a, { kind: "exited", pct: 0, boughtPct: share(g.bought) }); edges.push({ s: token, t: g.a, kind: "ghost" }); }
    const parent = new Map(); const find = (x) => { while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
    const join = (a, b) => { if (!parent.has(a)) parent.set(a, a); if (!parent.has(b)) parent.set(b, b); const ra = find(a), rb = find(b); if (ra !== rb) parent.set(ra, rb); };
    const why = new Map(); const tag = (a, r) => { if (!why.has(a)) why.set(a, new Set()); why.get(a).add(r); };
    // funding
    const byFunder = new Map();
    for (const [a, f] of funderOfMap) {
      if (infra.has(f.from) || BURNS.has(f.from)) continue;
      if (!byFunder.has(f.from)) byFunder.set(f.from, []);
      byFunder.get(f.from).push(a);
    }
    for (const [f, kids] of byFunder) {
      const inGraph = nodes.has(f);
      if (kids.length < 2 && !inGraph && f !== creator) continue; // a lone outside funder adds noise
      node(f, { kind: f === creator ? "creator" : "funder", pct: 0, label: f === creator ? "CREATOR" : "FUNDER" });
      for (const k of kids) { edges.push({ s: f, t: k, kind: "fund", eth: funderOfMap.get(k).eth }); if (kids.length >= 2 || f === creator || W.has(f)) { join(f, k); tag(k, f === creator ? "funded by creator" : "shared funder"); } }
    }
    // bursts
    bursts.forEach(([blk, set], i) => {
      const id = "blk:" + blk; node(id, { kind: "block", label: `BLK ${blk} · ${set.size} BUYS`, pct: 0, block: blk, count: set.size });
      for (const a of set) { if (!nodes.has(a)) continue; edges.push({ s: id, t: a, kind: "block" }); join(id, a); tag(a, "same-block buy"); }
    });
    // direct token transfers between non-infra addresses
    const pairSeen = new Set();
    for (const t of transfers) {
      if (infra.has(t.from) || infra.has(t.to) || BURNS.has(t.to) || t.from === t.to) continue;
      if (!nodes.has(t.from) || !nodes.has(t.to)) continue;
      const k = t.from + t.to; if (pairSeen.has(k)) continue; pairSeen.add(k);
      edges.push({ s: t.from, t: t.to, kind: t.from === creator ? "creator" : "send", pct: share(t.v) });
      join(t.from, t.to); tag(t.to, t.from === creator ? "received from creator" : "token transfer"); tag(t.from, "token transfer");
    }
    if (creator && nodes.has(creator)) { for (const t of transfers) if (t.from === creator && BURNS.has(t.to)) { node(t.to, { kind: "burn", label: "BURN", pct: 0 }); edges.push({ s: creator, t: t.to, kind: "burn", pct: share(t.v) }); } }

    // clusters
    const groups = new Map();
    for (const id of parent.keys()) { const r = find(id); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(id); }
    const clusters = [];
    for (const members of groups.values()) {
      const holdersIn = members.filter((m) => { const n = nodes.get(m); return n && (n.kind === "wallet" || n.kind === "creator"); });
      const exited = members.filter((m) => { const n = nodes.get(m); return n && n.kind === "exited"; });
      if (holdersIn.length + exited.length < 2) continue;
      const pct = holdersIn.reduce((s, m) => s + (nodes.get(m).pct || 0), 0);
      const reasons = new Set(); for (const m of members) for (const r of why.get(m) || []) reasons.add(r);
      clusters.push({ members, wallets: holdersIn.length, exited: exited.length, pct, reasons: [...reasons], hasCreator: members.includes(creator) });
    }
    clusters.sort((a, b) => b.pct - a.pct || b.wallets + b.exited - (a.wallets + a.exited));
    clusters.forEach((c, i) => { c.id = i + 1; for (const m of c.members) { const n = nodes.get(m); if (n) n.cluster = c.id; } });

    const walletNodes = [...nodes.values()].filter((n) => n.kind === "wallet");
    const linked = clusters.reduce((s, c) => s + c.pct, 0);
    const top = clusters[0];
    const summary = {
      holders: +(info.holders_count || info.holders || 0) || null, analyzed: walletNodes.length,
      clusters: clusters.length, linkedPct: linked, largestPct: top ? top.pct : 0,
      creatorLinkedPct: clusters.filter((c) => c.hasCreator).reduce((s, c) => s + c.pct, 0),
      bursts: bursts.map(([b, s]) => ({ block: b, buyers: s.size })), exited: ghosts.size,
      verdict: !clusters.length ? "No linked wallet groups among the top holders." :
        `${clusters.length} linked group${clusters.length > 1 ? "s" : ""} hold ${(linked * 100).toFixed(1)}% of supply · largest ${(top.pct * 100).toFixed(1)}% (${top.wallets} wallet${top.wallets === 1 ? "" : "s"}${top.exited ? `, ${top.exited} already exited` : ""}).`,
    };
    return {
      token, symbol: sym, name: info.name || null, decimals: dec, creator, fullHistory,
      nodes: [...nodes.values()], edges: edges.filter((e) => nodes.has(e.s) && nodes.has(e.t)),
      clusters: clusters.map(({ members, ...c }) => ({ ...c, size: members.length })), summary,
      builtAt: new Date().toISOString(),
      note: "Heuristic map from public on-chain data. A shared funder can be an exchange or a friend; linked is not proof of one owner.",
    };
  }

  async function map(token) {
    token = lc(token);
    const c = cache.get(token); if (c && Date.now() - c.at < CFG.ttl) return c.data;
    if (inflight.has(token)) return inflight.get(token);
    const p = build(token).then((data) => { cache.set(token, { at: Date.now(), data }); if (cache.size > 300) cache.delete(cache.keys().next().value); return data; }).finally(() => inflight.delete(token));
    inflight.set(token, p); return p;
  }
  return { map, cached: (t) => { const c = cache.get(lc(t)); return !!(c && Date.now() - c.at < CFG.ttl); } };
}
module.exports = { createCluster };
