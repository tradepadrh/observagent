// OBSERV AGENT server — live intelligence for Robinhood Chain.
// Data: DexPaprika (pools, prices, volume) + Robinhood Chain RPC (launchpad scanner, threat scanner, swap test, tx decode).
// Serves the web UI, a JSON API, an SSE stream and the AI endpoint. Node 18+, no dependencies.
// Data layer adapted from FISHY (github.com/oxhoodey/fishy).
const http = require("http");
const fs = require("fs");
const path = require("path");
const swaptest = require("./lib/swaptest");
const launchpads = require("./lib/launchpads");
const registry = require("./lib/registry");
const { createThreat } = require("./lib/threat");
const { createAI } = require("./lib/ai");

const env = (k, d = "") => (process.env[k] == null || process.env[k] === "" ? d : process.env[k]);
const CFG = {
  port: +env("PORT", 8787),
  host: env("HOST", "0.0.0.0"),
  chain: env("CHAIN", "robinhood"),
  limit: Math.min(100, +env("POOL_LIMIT", 100)),
  pages: Math.max(1, +env("POOL_PAGES", process.env.DEXPAPRIKA_API_KEY ? 2 : 1)),
  refreshMs: +env("REFRESH_SECONDS", 60) * 1000,
  statsMs: +env("STATS_SECONDS", 4) * 1000,
  minLiq: +env("MIN_LIQUIDITY", 1000),
  flowMin: +env("FLOW_MIN_USD", 250),
  liveLaunchMin: +env("LIVE_LAUNCH_MINUTES", 20),
  threatConcurrency: Math.max(1, +env("THREAT_CONCURRENCY", 1)),
  tzOffset: +env("DAILY_TZ_OFFSET", 7),
  apiBase: env("DEXPAPRIKA_BASE", "https://api.dexpaprika.com"),
  apiKey: env("DEXPAPRIKA_API_KEY"),
  apiKeyHeader: env("DEXPAPRIKA_API_KEY_HEADER", "authorization"),
  tokenLookups: +env("TOKEN_LOOKUPS_PER_REFRESH", 25),
};
// everything the page shows about the project comes from Railway variables
const SITE = () => ({
  PROJECT_NAME: env("PROJECT_NAME", "OBSERV AGENT"),
  TOKEN_TICKER: env("TOKEN_TICKER", "$OBSERV"),
  TOKEN_CA: env("TOKEN_CA"),
  CHAIN_NAME: env("CHAIN_NAME", "Robinhood Chain"),
  CHAIN_ID: +env("CHAIN_ID", 4663),
  LAUNCHPAD_NAME: env("LAUNCHPAD_NAME", "Pons"),
  LAUNCHPAD_URL: env("LAUNCHPAD_URL"),
  EXPLORER_URL: env("EXPLORER_URL", "https://robinhoodchain.blockscout.com").replace(/\/$/, ""),
  PROJECT_X: env("PROJECT_X"),
  TELEGRAM_URL: env("TELEGRAM_URL"),
  WEBSITE_URL: env("WEBSITE_URL"),
  DEV_NAME: env("DEV_NAME"),
  DEV_X: env("DEV_X"),
  DEV_ROLE: env("DEV_ROLE", "Founder · Builder"),
  DEV_BIO: env("DEV_BIO", "Building autonomous on-chain intelligence for Robinhood Chain."),
  SITE_URL: env("SITE_URL").replace(/\/$/, ""),
  API_BASE_URL: env("API_BASE_URL", env("SITE_URL")).replace(/\/$/, ""),
  MCP_URL: env("MCP_URL"),
});

const STABLE = new Set(["USDG", "USDC", "USDT", "DAI", "USDE"]);
const BLUE = new Set(["WETH", "ETH", "WBTC", "CBBTC", "ARB", "LINK", "UNI"]);
const STOCK = new Set(env("STOCK_SYMBOLS", "TSLA,NVDA,AAPL,AMZN,SPY,QQQ,HOOD,MSFT,GOOGL,META,COIN,MSTR,AMD,NFLX,PLTR,SPCX").split(",").map((s) => s.trim().toUpperCase()).filter(Boolean));
const category = (sym) => { const s = String(sym || "").toUpperCase(); return STABLE.has(s) ? "stable" : BLUE.has(s) ? "blue" : STOCK.has(s) ? "stock" : "meme"; };
const HUBS = new Set(["WETH", "ETH", ...STABLE]);
const num = (v) => (v == null || v === "" || isNaN(+v) ? null : +v);
const lc = (s) => String(s || "").toLowerCase();
const isAddr = (a) => /^0x[0-9a-fA-F]{40}$/.test(String(a || ""));

// ---------------------------------------------------------------- DexPaprika
const TOKEN_META = new Map([["0x0000000000000000000000000000000000000000", { symbol: "ETH", name: "Ether (native)" }]]);
const headers = () => (CFG.apiKey ? { accept: "application/json", [CFG.apiKeyHeader]: CFG.apiKey } : { accept: "application/json" });
async function dpGet(pq) {
  const r = await fetch(`${CFG.apiBase}${pq}`, { headers: headers(), signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`DexPaprika ${r.status}`);
  return r.json();
}
function normalize(p) {
  const t = Array.isArray(p.tokens) ? p.tokens : [];
  if (t.length < 2) return null;
  const tok = (x) => {
    if (typeof x === "string") x = { id: x };
    const id = String(x.id || x.address || x.token_address || "?"), meta = TOKEN_META.get(lc(id)) || {};
    const sh = id.length > 12 ? id.slice(0, 6) + "…" + id.slice(-4) : id;
    const sym = String(x.symbol || meta.symbol || x.name || meta.name || sh).slice(0, 16);
    return { id, sym, name: String(x.name || meta.name || sym).slice(0, 48), cat: category(sym), fdv: num(x.fdv) };
  };
  return { id: String(p.id), dex: p.dex_name || p.dex_id || "", a: tok(t[0]), b: tok(t[1]), vol: num(p.volume_usd_24h ?? p.volume_usd) || 0, liq: num(p.liquidity_usd ?? p.liquidity) || 0, chg: num(p.price_change_percentage_24h), price: num(p.price_usd), fee: num(p.fee), createdBlock: num(p.created_at_block_number), created: p.created_at || null, txns: num(p.transactions ?? p.txns_24h) };
}
async function enrichTokens(raw) {
  const missing = new Set();
  for (const p of raw) for (const x of Array.isArray(p.tokens) ? p.tokens : []) {
    const o = typeof x === "string" ? { id: x } : x || {}, id = lc(o.id || o.address);
    if (!id) continue;
    if (o.symbol) { if (!TOKEN_META.has(id)) TOKEN_META.set(id, { symbol: o.symbol, name: o.name }); continue; }
    if (!TOKEN_META.has(id)) missing.add(id);
  }
  const todo = [...missing].slice(0, CFG.tokenLookups);
  for (let i = 0; i < todo.length; i += 5) await Promise.all(todo.slice(i, i + 5).map(async (id) => {
    try { const j = await dpGet(`/networks/${CFG.chain}/tokens/${id}`), t = j.token || j; if (t && (t.symbol || t.name)) TOKEN_META.set(id, { symbol: t.symbol, name: t.name }); } catch (_) {}
  }));
}
async function fetchPools() {
  const all = []; let cursor = "";
  for (let i = 0; i < CFG.pages; i++) {
    const url = `/pools/search?chains=${CFG.chain}&order_by=volume_usd_24h&sort=desc&limit=${CFG.limit}&detailed=true${cursor ? "&cursor=" + encodeURIComponent(cursor) : ""}`;
    let j;
    try { j = await dpGet(url); } catch (e) { if (i > 0 && all.length) break; throw e; }
    all.push(...(j.results || []));
    if (!j.has_next_page || !j.next_cursor) break;
    cursor = j.next_cursor;
  }
  return all;
}
const fetchNewPools = async () => (await dpGet(`/networks/${CFG.chain}/pools/search?order_by=created_at&sort=desc&limit=100&detailed=true`)).results || [];
const LOOKUP = new Map();
async function lookupToken(addr) {
  const a = lc(addr), hit = LOOKUP.get(a);
  if (hit && Date.now() - hit.t < 60000) return hit.d;
  const j = await dpGet(`/networks/${CFG.chain}/pools/search?token_address=${a}&order_by=liquidity_usd&sort=desc&limit=25&detailed=true`);
  const raw = j.results || [];
  await enrichTokens(raw);
  const d = { address: a, pools: raw.map(normalize).filter(Boolean), updatedAt: new Date().toISOString() };
  LOOKUP.set(a, { t: Date.now(), d });
  if (LOOKUP.size > 500) LOOKUP.delete(LOOKUP.keys().next().value);
  return d;
}
const subject = (p) => (HUBS.has(p.a.sym.toUpperCase()) && !HUBS.has(p.b.sym.toUpperCase()) ? [p.b, p.a] : [p.a, p.b]);
function quoteUsdOf(sym) {
  const s = String(sym || "").toUpperCase();
  if (STABLE.has(s)) return 1;
  if (s === "WETH" || s === "ETH") {
    const p = snapshot.pools.filter((x) => ["WETH", "ETH"].includes(x.a.sym.toUpperCase()) && STABLE.has(x.b.sym.toUpperCase()) && x.price > 0).sort((a, b) => b.liq - a.liq)[0];
    return p ? p.price : null;
  }
  return null;
}
// the real stock token for each ticker = the deepest one (used so the threat scanner never flags it as a clone)
function stockOfficial() {
  const best = new Map();
  for (const p of snapshot.pools) for (const t of [p.a, p.b]) if (t.cat === "stock") { const b = best.get(t.sym.toUpperCase()); if (!b || p.liq > b.liq) best.set(t.sym.toUpperCase(), { id: lc(t.id), liq: p.liq }); }
  return new Map([...best].map(([k, v]) => [k, v.id]));
}

// ---------------------------------------------------------------- swap test (Uniswap quoters)
const swapCache = new Map();
async function swapTestToken(tokenId, usd) {
  const k = lc(tokenId) + ":" + usd, c = swapCache.get(k);
  if (c && Date.now() - c.at < 120000) return c.data;
  let pools = snapshot.pools.filter((p) => lc(p.a.id) === lc(tokenId) || lc(p.b.id) === lc(tokenId));
  if (!pools.length) { try { pools = (await lookupToken(tokenId)).pools; } catch (_) {} }
  pools = pools.filter((p) => p.liq >= CFG.minLiq).sort((a, b) => b.liq - a.liq).slice(0, 3);
  const results = [];
  for (const p of pools) {
    const q = lc(p.a.id) === lc(tokenId) ? p.b : p.a, qUsd = quoteUsdOf(q.sym);
    if (!qUsd) { results.push({ pool: p.id, dex: p.dex, quote: q.sym, error: "no USD price for " + q.sym }); continue; }
    try { results.push(await swaptest.roundTrip(p, tokenId, usd, qUsd)); } catch (e) { results.push({ pool: p.id, dex: p.dex, quote: q.sym, error: String(e.message || e) }); }
  }
  const ok = results.filter((r) => !r.error).sort((a, b) => a.lossPct - b.lossPct);
  const data = { token: tokenId, usd, at: new Date().toISOString(), best: ok[0] || null, results };
  swapCache.set(k, { at: Date.now(), data });
  if (swapCache.size > 500) swapCache.delete(swapCache.keys().next().value);
  return data;
}

// ---------------------------------------------------------------- state, events, SSE
let snapshot = { updatedAt: null, error: null, pools: [], newTokens: [] };
const stats = { block: null, gasGwei: null, tps: null, bps: null, scanner: null, updatedAt: null };
const feed = []; // newest first
const clients = new Set();
let evSeq = 0;
function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(msg);
}
function pushEvent(type, data) {
  const ev = { id: ++evSeq, type, t: new Date().toISOString(), ...data };
  feed.unshift(ev);
  if (feed.length > 400) feed.pop();
  countDaily(ev);
  broadcast("event", ev);
  return ev;
}
const within = (ms) => feed.filter((e) => Date.now() - Date.parse(e.t) < ms);

// daily counters (local day, UTC+DAILY_TZ_OFFSET). In memory: a restart starts a fresh count.
let daily = null;
const dayKey = () => new Date(Date.now() + CFG.tzOffset * 3600e3).toISOString().slice(0, 10);
function ensureDay() {
  const k = dayKey();
  if (!daily || daily.day !== k) daily = { day: k, since: new Date().toISOString(), launches: 0, byPad: {}, pools: 0, graduations: 0, threats: 0, flows: {}, hours: Array(24).fill(0) };
}
function countDaily(ev) {
  ensureDay();
  const h = new Date(Date.now() + CFG.tzOffset * 3600e3).getUTCHours();
  daily.hours[h]++;
  if (ev.type === "launch") { daily.launches++; daily.byPad[ev.pad] = (daily.byPad[ev.pad] || 0) + 1; }
  if (ev.type === "pool") daily.pools++;
  if (ev.type === "graduate") daily.graduations++;
  if (ev.type === "threat") daily.threats++;
  if (ev.type === "flow") daily.flows[ev.sym] = (daily.flows[ev.sym] || 0) + ev.usd;
}

// ---------------------------------------------------------------- threat scanner queue
const threat = createThreat({
  launchpads, lookupToken, swapTestToken, pools: () => snapshot.pools, stockSyms: STOCK, stockOfficial,
  official: { ca: SITE().TOKEN_CA, ticker: SITE().TOKEN_TICKER, name: SITE().PROJECT_NAME },
});
const queue = []; const queued = new Set(); let running = 0;
function enqueue(addr, front = false) {
  const a = lc(addr);
  if (!isAddr(a) || queued.has(a) || threat.cached(a)) return;
  queued.add(a); front ? queue.unshift(a) : queue.push(a);
  if (queue.length > 300) queued.delete(queue.pop());
  pump();
}
const summary = (r) => ({ token: r.token, symbol: r.symbol, launchpad: r.launchpad, score: r.score, level: r.level, top: r.signals[0] ? r.signals[0].label : null, signals: r.signals.map((s) => s.label) });
function pump() {
  while (running < CFG.threatConcurrency && queue.length) {
    const a = queue.shift(); running++;
    threat.scan(a).then((r) => {
      broadcast("scan", summary(r));
      if (r.score >= 50) pushEvent("threat", { ...summary(r), evidence: r.signals[0] && r.signals[0].evidence });
    }).catch((e) => console.warn("threat scan", a, e.message)).finally(() => { running--; queued.delete(a); pump(); });
  }
}

// ---------------------------------------------------------------- launches (on-chain scanner)
const padName = (key) => { const p = launchpads.PADS.find((x) => x.key === key); return p ? p.name : String(key || "DEX").toUpperCase(); };
launchpads.onLaunch((l) => {
  const age = Date.now() - Date.parse(l.created || 0);
  if (age < CFG.liveLaunchMin * 60000) {
    pushEvent("launch", { token: l.id, sym: l.sym, name: l.name, pad: l.pad, padName: l.padName, block: l.block, created: l.created, deployer: l.deployer || null, tx: l.tx || null });
    enqueue(l.id, true);
  } else if (launchpads.all().length - l.seq < 40) enqueue(l.id); // backfill: scan only the newest few
});
const graduated = new Set();

// ---------------------------------------------------------------- DexPaprika refresh
const seenPools = new Set(); let prevVol = new Map(); let firstRefresh = true;
async function refresh() {
  try {
    const raw = await fetchPools();
    let rawNew = [];
    try { rawNew = await fetchNewPools(); } catch (e) { console.warn("new pools:", e.message); }
    await enrichTokens(raw.concat(rawNew));
    const ids = new Set(raw.map((p) => String(p.id)));
    const pools = raw.concat(rawNew.filter((p) => !ids.has(String(p.id)))).map(normalize).filter(Boolean);
    if (!pools.length) throw new Error("DexPaprika returned no pools");
    snapshot = { ...snapshot, updatedAt: new Date().toISOString(), error: null, pools };

    // equity flows: growth of each stock token's 24h volume since the last refresh (a lower bound of new trading)
    const flow = new Map();
    for (const p of pools) {
      const st = p.a.cat === "stock" ? p.a : p.b.cat === "stock" ? p.b : null;
      const before = prevVol.get(p.id);
      if (st && before != null && p.vol > before) { const f = flow.get(st.sym) || { usd: 0, pool: p.id, dex: p.dex, id: st.id }; f.usd += p.vol - before; flow.set(st.sym, f); }
    }
    prevVol = new Map(pools.map((p) => [p.id, p.vol]));
    for (const [sym, f] of [...flow].sort((a, b) => b[1].usd - a[1].usd).slice(0, 6)) if (f.usd >= CFG.flowMin) pushEvent("flow", { sym, usd: Math.round(f.usd), token: f.id, pool: f.pool, dex: f.dex });

    // new DEX pools (+ graduations of tokens we saw launching on a curve)
    for (const p of rawNew.map(normalize).filter(Boolean)) {
      if (seenPools.has(p.id)) continue;
      seenPools.add(p.id);
      if (firstRefresh) continue;
      const [tok, pair] = subject(p);
      if (HUBS.has(tok.sym.toUpperCase()) || tok.cat === "stock") continue;
      const L = launchpads.get(tok.id);
      if (L && !graduated.has(lc(tok.id))) { graduated.add(lc(tok.id)); pushEvent("graduate", { token: lc(tok.id), sym: L.sym || tok.sym, pad: L.pad, padName: L.padName, pool: p.id, dex: p.dex, liq: Math.round(p.liq) }); }
      else pushEvent("pool", { token: lc(tok.id), sym: tok.sym, pair: pair.sym, pool: p.id, dex: p.dex, liq: Math.round(p.liq), pad: L ? L.pad : "dex" });
      enqueue(tok.id);
    }
    // graduations of scanner tokens that now trade on a DEX (also catches pools outside the newest-100 list)
    const onDex = new Set(); for (const p of pools) { onDex.add(lc(p.a.id)); onDex.add(lc(p.b.id)); }
    for (const l of launchpads.all()) if (onDex.has(l.id) && !graduated.has(l.id)) { graduated.add(l.id); if (!firstRefresh) pushEvent("graduate", { token: l.id, sym: l.sym, pad: l.pad, padName: l.padName }); }
    firstRefresh = false;
    broadcast("market", marketSummary());
    console.log(`[${snapshot.updatedAt}] ${pools.length} pools · feed ${feed.length} · scanner ${launchpads.all().length}`);
  } catch (e) { snapshot.error = String(e.message || e); console.error("refresh failed:", snapshot.error); }
}
function marketSummary() {
  const P = snapshot.pools;
  const vol = P.reduce((s, p) => s + p.vol, 0), liq = P.reduce((s, p) => s + p.liq, 0);
  const eq = new Map();
  for (const p of P) { const st = p.a.cat === "stock" ? p.a : p.b.cat === "stock" ? p.b : null; if (st) eq.set(st.sym, (eq.get(st.sym) || 0) + p.vol); }
  return { updatedAt: snapshot.updatedAt, pools: P.length, volume24hUsd: Math.round(vol), liquidityUsd: Math.round(liq), equities: [...eq].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([sym, v]) => ({ sym, volume24hUsd: Math.round(v) })) };
}

// ---------------------------------------------------------------- network stats (RPC)
let lastBlk = null;
async function pollStats() {
  try {
    const [bn, gp, blk] = await Promise.all([swaptest.rpc("eth_blockNumber", []), swaptest.rpc("eth_gasPrice", []).catch(() => null), swaptest.rpc("eth_getBlockByNumber", ["latest", false]).catch(() => null)]);
    const b = parseInt(bn, 16), now = Date.now();
    if (lastBlk && b > lastBlk.b) {
      const bps = (b - lastBlk.b) / ((now - lastBlk.t) / 1000);
      stats.bps = stats.bps ? stats.bps * 0.7 + bps * 0.3 : bps;
    }
    lastBlk = { b, t: now };
    const txs = blk && Array.isArray(blk.transactions) ? blk.transactions.length : null;
    if (txs != null && stats.bps) { const tps = txs * stats.bps; stats.tps = stats.tps ? stats.tps * 0.8 + tps * 0.2 : tps; }
    Object.assign(stats, { block: b, gasGwei: gp ? parseInt(gp, 16) / 1e9 : stats.gasGwei, updatedAt: new Date().toISOString(), scanner: launchpads.status() });
    broadcast("stats", publicStats());
  } catch (e) { stats.error = String(e.message || e); }
}
const publicStats = () => ({ block: stats.block, gasGwei: stats.gasGwei, tps: stats.tps ? Math.round(stats.tps) : null, bps: stats.bps ? +stats.bps.toFixed(1) : null, updatedAt: stats.updatedAt, scanner: stats.scanner ? { last: stats.scanner.last, tracked: stats.scanner.tracked, lastError: stats.scanner.lastError } : null });

// ---------------------------------------------------------------- read models
function tokenCard(l) {
  const r = threat.cached(l.id);
  return { token: l.id, sym: l.sym, name: l.name, pad: l.pad, padName: l.padName, block: l.block, created: l.created, deployer: l.deployer || null, seq: l.seq, graduated: graduated.has(l.id) || !!l.graduated, threat: r ? summary(r) : null };
}
const recentTokens = (n = 60) => launchpads.all().filter((l) => l.sym && l.created).sort((a, b) => b.block - a.block).slice(0, n).map(tokenCard);
function liveStats(windowSec = 300) {
  const ws = Math.min(Math.max(+windowSec || 300, 10), 3600), f = within(ws * 1000);
  const c = (t) => f.filter((e) => e.type === t);
  const byPad = {}; for (const e of c("launch")) byPad[e.padName || e.pad] = (byPad[e.padName || e.pad] || 0) + 1;
  const flows = {}; for (const e of c("flow")) flows[e.sym] = (flows[e.sym] || 0) + e.usd;
  return { window_seconds: ws, network: publicStats(), market: marketSummary(), token_launches: c("launch").length, launches_by_launchpad: byPad, new_dex_pools: c("pool").length, graduations: c("graduate").length, threat_flags: c("threat").length, equity_flow_usd: flows, note: "OBSERV counts events since the server started watching; market figures are DexPaprika 24h numbers." };
}
function coverage() {
  const reg = registry.forWeb(launchpads.PADS), f5 = within(300000), all = launchpads.all();
  const pads = reg.launchpads.map((p) => {
    const toks = all.filter((l) => l.pad === p.id);
    return { ...p, geneses5m: f5.filter((e) => e.type === "launch" && e.pad === p.id).length, tracked: toks.length, flagged: toks.filter((l) => { const r = threat.cached(l.id); return r && r.score >= 50; }).length };
  });
  return { chains: reg.chains, launchpads: pads, scanner: launchpads.status() };
}
async function genesis(ca) {
  const a = lc(ca), L = launchpads.get(a);
  const [scan, dex] = await Promise.all([threat.scan(a), lookupToken(a).catch(() => ({ pools: [] }))]);
  return { token: a, launch: L ? tokenCard(L) : null, pools: (dex.pools || []).slice(0, 5).map((p) => ({ id: p.id, dex: p.dex, pair: `${p.a.sym}/${p.b.sym}`, liq: Math.round(p.liq), vol: Math.round(p.vol), price: p.price, created: p.created })), threat: scan, explorer: `${SITE().EXPLORER_URL}/token/${a}` };
}
const T_TRANSFER = swaptest.keccak256("Transfer(address,address,uint256)");
const METHODS = { "0xa9059cbb": "transfer", "0x095ea7b3": "approve", "0x23b872dd": "transferFrom", "0x3593564c": "execute (Universal Router)", "0x24856bc3": "execute (Universal Router)", "0x7ff36ab5": "swapExactETHForTokens", "0x18cbafe5": "swapExactTokensForETH", "0x38ed1739": "swapExactTokensForTokens", "0x414bf389": "exactInputSingle", "0x04e45aaf": "exactInputSingle", "0xd0e30db0": "deposit (wrap ETH)", "0x2e1a7d4d": "withdraw (unwrap ETH)", "0x60806040": "contract creation" };
async function decodeTx(hash) {
  const [tx, rc] = await Promise.all([swaptest.rpc("eth_getTransactionByHash", [hash]), swaptest.rpc("eth_getTransactionReceipt", [hash])]);
  if (!tx) { const e = new Error("transaction not found on this chain"); e.code = 404; throw e; }
  const transfers = [];
  for (const lg of (rc && rc.logs) || []) if (lg.topics[0] === T_TRANSFER && lg.topics.length === 3) transfers.push({ token: lc(lg.address), from: "0x" + lg.topics[1].slice(-40), to: "0x" + lg.topics[2].slice(-40), raw: BigInt(lg.data && lg.data !== "0x" ? lg.data : "0x0") });
  const metas = new Map();
  for (const t of [...new Set(transfers.map((x) => x.token))].slice(0, 6)) { try { metas.set(t, await launchpads.erc20Meta(t)); } catch (_) {} }
  const sel = String(tx.input || "0x").slice(0, 10), gasUsed = rc ? parseInt(rc.gasUsed, 16) : null, price = rc && rc.effectiveGasPrice ? parseInt(rc.effectiveGasPrice, 16) : parseInt(tx.gasPrice || "0x0", 16);
  return {
    hash, block: tx.blockNumber ? parseInt(tx.blockNumber, 16) : null, status: rc ? (rc.status === "0x1" ? "success" : "reverted") : "pending",
    from: lc(tx.from), to: tx.to ? lc(tx.to) : null, created: rc && rc.contractAddress ? lc(rc.contractAddress) : null,
    valueEth: Number(BigInt(tx.value || "0x0")) / 1e18, method: METHODS[sel] || (tx.to ? `unknown (${sel})` : "contract creation"),
    gasUsed, feeEth: gasUsed && price ? (gasUsed * price) / 1e18 : null, logs: rc ? rc.logs.length : 0,
    toLaunchpad: tx.to ? (launchpads.PADS.find((p) => (p.addrs || []).map(lc).includes(lc(tx.to))) || {}).name || null : null,
    transfers: transfers.slice(0, 12).map((x) => { const m = metas.get(x.token) || {}; const d = m.decimals == null ? 18 : m.decimals; return { token: x.token, symbol: m.symbol || null, from: lc(x.from), to: lc(x.to), amount: Number(x.raw) / 10 ** d, launchpad: (launchpads.get(x.token) || {}).padName || null }; }),
    explorer: `${SITE().EXPLORER_URL}/tx/${hash}`,
  };
}
function dailyReport() {
  ensureDay();
  const m = marketSummary();
  const scans = threat.recent().filter((r) => Date.parse(r.scannedAt) > Date.parse(daily.since));
  return { ...daily, market: m, flagged: scans.filter((r) => r.score >= 50).length, scanned: scans.length, note: "Event counts cover the time this server has been watching today; market figures are DexPaprika 24h values." };
}
function projectInfo() {
  const s = SITE(), ca = isAddr(s.TOKEN_CA) ? s.TOKEN_CA : null;
  return { project: s.PROJECT_NAME, ticker: s.TOKEN_TICKER, status: ca ? "live" : "pre-launch", contract_address: ca, chain: s.CHAIN_NAME, chain_id: s.CHAIN_ID, launchpad: s.LAUNCHPAD_NAME, launchpad_url: s.LAUNCHPAD_URL || null, explorer_url: ca ? `${s.EXPLORER_URL}/token/${ca}` : null, project_x: s.PROJECT_X ? "@" + s.PROJECT_X.replace(/^@/, "") : null, developer: { name: s.DEV_NAME || null, x: s.DEV_X ? "@" + s.DEV_X.replace(/^@/, "") : null, role: s.DEV_ROLE || null }, telegram: s.TELEGRAM_URL || null, website: s.WEBSITE_URL || null };
}
function contextPack() {
  return { source: SITE().PROJECT_NAME, kind: "live snapshot", generated_at: new Date().toISOString(), network: { chain: SITE().CHAIN_NAME, chain_id: SITE().CHAIN_ID, ...publicStats() }, stats_5m: liveStats(300), latest_geneses: recentTokens(12).map((t) => ({ token: t.sym, contract: t.token, launchpad: t.padName, created: t.created, threat_score: t.threat ? t.threat.score : null, threat_level: t.threat ? t.threat.level : "not scanned yet", signals: t.threat ? t.threat.signals : [] })), coverage: coverage().launchpads.filter((p) => !p.standby).map((p) => ({ launchpad: p.name, geneses_5m: p.geneses5m, tracked: p.tracked })), official_project: projectInfo() };
}

// ---------------------------------------------------------------- AI tools over the read models
const AI_TOOLS = [
  { name: "get_live_stats", description: "Live Robinhood Chain telemetry over a window (seconds, 10-3600): block, gas, tx/s, token launches per launchpad, new DEX pools, graduations, threat flags, stock-token flows, DexPaprika 24h market totals.", input_schema: { type: "object", properties: { window_seconds: { type: "integer" } } }, run: (i) => liveStats(i.window_seconds) },
  { name: "get_recent_events", description: "Latest events: launch, pool, graduate, flow, threat.", input_schema: { type: "object", properties: { type: { type: "string", enum: ["any", "launch", "pool", "graduate", "flow", "threat"] }, limit: { type: "integer" } } }, run: (i) => feed.filter((e) => !i.type || i.type === "any" || e.type === i.type).slice(0, Math.min(20, i.limit || 8)) },
  { name: "get_token", description: "Launch record + DEX pools for one token. Pass ca (0x address) or symbol; omit both for the newest launch.", input_schema: { type: "object", properties: { ca: { type: "string" }, symbol: { type: "string" } } }, run: async (i) => { let a = isAddr(i.ca) ? lc(i.ca) : null; if (!a && i.symbol) { const l = launchpads.all().filter((x) => lc(x.sym) === lc(String(i.symbol).replace("$", ""))).sort((x, y) => y.block - x.block)[0]; a = l && l.id; } if (!a) { const t = recentTokens(1)[0]; a = t && t.token; } if (!a) throw new Error("no token found"); const L = launchpads.get(a), d = await lookupToken(a).catch(() => ({ pools: [] })); return { token: a, launch: L ? tokenCard(L) : null, pools: d.pools.slice(0, 3).map((p) => ({ dex: p.dex, pair: `${p.a.sym}/${p.b.sym}`, liq: Math.round(p.liq), vol24h: Math.round(p.vol) })) }; } },
  { name: "scan_token_risk", description: "Heuristic threat scan of a token (creator concentration, creator exit, top-10 concentration, bundled genesis, serial launcher, ticker impersonation, swap test / honeypot, hook tax, thin exit, inflated volume). Pass ca, or highest=true for the riskiest recent token (optionally filtered by launchpad key).", input_schema: { type: "object", properties: { ca: { type: "string" }, highest: { type: "boolean" }, launchpad: { type: "string" } } }, run: async (i) => { if (isAddr(i.ca)) return threat.scan(i.ca); const pool = threat.recent().filter((r) => !i.launchpad || r.launchpad === i.launchpad); if (i.highest || !pool.length) { const top = pool.sort((a, b) => b.score - a.score)[0]; if (top) return top; } const t = recentTokens(1)[0]; if (!t) throw new Error("no token scanned yet"); return threat.scan(t.token); } },
  { name: "get_coverage", description: "Chains and launchpads OBSERV AGENT watches (live / planned / research) with 5-minute genesis counts and flagged tokens per launchpad.", input_schema: { type: "object", properties: {} }, run: () => coverage() },
  { name: "get_project_info", description: "Official info about this project's own token and team: ticker, contract address or pre-launch status, links, developer.", input_schema: { type: "object", properties: {} }, run: () => projectInfo() },
];
const ai = createAI(AI_TOOLS);

// ---------------------------------------------------------------- HTTP
const PUB = path.join(__dirname, "public");
const MIME = { ".html": "text/html; charset=utf-8", ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".json": "application/json", ".txt": "text/plain; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
let INDEX = null;
function renderIndex() {
  if (!INDEX || process.env.NODE_ENV !== "production") INDEX = fs.readFileSync(path.join(PUB, "index.html"), "utf8");
  const boot = `window.OBSERV_ENV=${JSON.stringify({ ...SITE(), AI_ENABLED: ai.enabled() })};window.OBSERV_REGISTRY=${JSON.stringify(registry.forWeb(launchpads.PADS))};`;
  return INDEX.replace("/*OBSERV_BOOT*/", boot.replace(/</g, "\\u003c"));
}
function send(res, code, body, type = "application/json; charset=utf-8") {
  res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*", "cache-control": "no-store" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}
const json = (res, p) => Promise.resolve(p).then((d) => send(res, 200, d)).catch((e) => send(res, e.code === 404 ? 404 : 502, { error: String(e.message || e) }));
function readBody(req, max = 8000) {
  return new Promise((ok, no) => { let s = ""; req.on("data", (c) => { s += c; if (s.length > max) { no(new Error("body too large")); req.destroy(); } }); req.on("end", () => { try { ok(JSON.parse(s || "{}")); } catch (e) { no(e); } }); });
}
// heavy endpoints (RPC scans, decoding) are rate-limited per IP to protect the RPC and DexPaprika quotas
const HEAVY_PER_MIN = +env("HEAVY_PER_IP_PER_MINUTE", 20), heavyHits = new Map();
function heavyLimited(ip) {
  const now = Date.now(), arr = (heavyHits.get(ip) || []).filter((t) => now - t < 60000);
  if (arr.length >= HEAVY_PER_MIN) return true;
  arr.push(now); heavyHits.set(ip, arr);
  if (heavyHits.size > 5000) heavyHits.delete(heavyHits.keys().next().value);
  return false;
}
const clientIp = (req) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?").split(",")[0].trim();

const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x"), p = u.pathname, tail = decodeURIComponent(p.split("/").pop() || "");
  if (req.method === "OPTIONS") { res.writeHead(204, { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST", "access-control-allow-headers": "content-type" }); return res.end(); }
  if (p === "/api/health") return send(res, 200, { ok: !snapshot.error && !!snapshot.updatedAt, updatedAt: snapshot.updatedAt, pools: snapshot.pools.length, error: snapshot.error, block: stats.block, scanner: launchpads.status(), ai: ai.enabled(), clients: clients.size });
  if (p === "/api/config") return send(res, 200, { ...SITE(), AI_ENABLED: ai.enabled() });
  if (p === "/api/registry") return send(res, 200, registry.forWeb(launchpads.PADS));
  if (p === "/api/state") return send(res, 200, { stats: publicStats(), market: marketSummary(), feed: feed.slice(0, 80), tokens: recentTokens(60), updatedAt: snapshot.updatedAt });
  if (p === "/api/stats") return send(res, 200, liveStats(+u.searchParams.get("window") || 300));
  if (p === "/api/feed") return send(res, 200, feed.slice(0, Math.min(400, +u.searchParams.get("limit") || 100)));
  if (p === "/api/tokens") return send(res, 200, recentTokens(Math.min(300, +u.searchParams.get("limit") || 60)));
  if (p === "/api/coverage") return send(res, 200, coverage());
  if (p === "/api/daily") return send(res, 200, dailyReport());
  if (p === "/api/project") return send(res, 200, projectInfo());
  if (p === "/api/kit/context") return send(res, 200, contextPack());
  if (p === "/api/radar") { const pad = u.searchParams.get("pad"); return send(res, 200, threat.recent().filter((r) => !pad || pad === "all" || r.launchpad === pad).sort((a, b) => b.score - a.score).slice(0, 40).map(summary)); }
  if (/^\/api\/(genesis|threat|tx|swaptest)\//.test(p) && !threat.cached(tail) && heavyLimited(clientIp(req))) return send(res, 429, { error: "Too many scans — wait a minute." });
  if (p.startsWith("/api/genesis/")) { if (!isAddr(tail)) return send(res, 400, { error: "send a 0x contract address" }); return json(res, genesis(tail)); }
  if (p.startsWith("/api/threat/")) { if (!isAddr(tail)) return send(res, 400, { error: "send a 0x contract address" }); return json(res, threat.scan(tail, { force: u.searchParams.get("fresh") === "1" })); }
  if (p.startsWith("/api/tx/")) { if (!/^0x[0-9a-fA-F]{64}$/.test(tail)) return send(res, 400, { error: "send a 0x transaction hash (64 hex characters)" }); return json(res, decodeTx(lc(tail))); }
  if (p.startsWith("/api/swaptest/")) { if (!isAddr(tail)) return send(res, 400, { error: "bad address" }); return json(res, swapTestToken(tail, Math.min(1e5, Math.max(1, +u.searchParams.get("usd") || 50)))); }
  if (p === "/api/launchpads") return send(res, 200, launchpads.status());
  if (p === "/api/ask" && req.method === "POST") {
    readBody(req).then(async (b) => {
      const ctx = { official: { name: SITE().PROJECT_NAME }, padNames: registry.forWeb(launchpads.PADS).launchpads.filter((x) => !x.standby && x.id !== "dex").map((x) => x.name) };
      const r = await ai.ask({ q: b.q, history: Array.isArray(b.history) ? b.history : [], ip: clientIp(req) }, ctx);
      send(res, r.status, r.body);
    }).catch((e) => send(res, 400, { error: String(e.message || e) }));
    return;
  }
  if (p === "/api/stream") {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive", "access-control-allow-origin": "*", "x-accel-buffering": "no" });
    res.write(`retry: 5000\n\n`);
    res.write(`event: stats\ndata: ${JSON.stringify(publicStats())}\n\n`);
    clients.add(res);
    const ping = setInterval(() => res.write(`: ping\n\n`), 25000);
    req.on("close", () => { clearInterval(ping); clients.delete(res); });
    return;
  }
  if (p === "/" || p === "/index.html") { try { return send(res, 200, renderIndex(), MIME[".html"]); } catch (e) { return send(res, 500, { error: "index missing" }); } }
  const rel = path.normalize(decodeURIComponent(p)).replace(/^([/\\.])+/, ""), file = path.join(PUB, rel), ext = path.extname(file).toLowerCase();
  if (file.startsWith(PUB + path.sep) && MIME[ext] && ext !== ".html") return fs.readFile(file, (err, buf) => { if (err) return send(res, 404, { error: "not found" }); res.writeHead(200, { "content-type": MIME[ext], "cache-control": "public, max-age=3600" }); res.end(buf); });
  send(res, 404, { error: "not found" });
});

if (require.main === module) {
  server.listen(CFG.port, CFG.host, () => console.log(`OBSERV AGENT on http://${CFG.host}:${CFG.port} · chain=${CFG.chain} · ai=${ai.enabled() ? ai.model() : "off"}`));
  const stop = () => { for (const c of clients) c.end(); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 3000).unref(); };
  process.on("SIGTERM", stop); process.on("SIGINT", stop);
  refresh(); setInterval(refresh, CFG.refreshMs);
  pollStats(); setInterval(pollStats, CFG.statsMs);
  if (env("LAUNCHPAD_SCAN", "1") !== "0") {
    let busy = false;
    const tick = async () => { if (busy) return; busy = true; try { await launchpads.scan(); } catch (e) { console.warn("launchpad scan:", e.message); } busy = false; };
    tick(); setInterval(tick, +env("LAUNCH_SCAN_MS", 20000));
  }
}
module.exports = { server, normalize, liveStats, coverage, decodeTx };
