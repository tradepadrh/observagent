// Launchpad scanner: reads new tokens straight from Robinhood Chain (RPC), so tokens still on a bonding curve
// show up even though DexPaprika only indexes Uniswap V2/V3/V4.
//  - Pons V2: TokenLaunched on the factory + CurveBuy/CurveSell on each token's curve (signatures checked against Bitquery's topic0 list)
//  - Other launchpads: a new ERC-20 minted (Transfer from 0x0) to, or in a transaction sent to, a known launchpad contract
//    (the same rule Bitquery uses); Flap tokens also carry vanity 8888/7777 addresses (Flap docs).
const { keccak256, rpc } = require("./swaptest");
const listeners = [];
const onLaunch = (fn) => listeners.push(fn);

const T_TRANSFER = keccak256("Transfer(address,address,uint256)");
const T_LAUNCH = keccak256("TokenLaunched(address,address,address,address,uint256,uint256)");
const T_BUY = keccak256("CurveBuy(address,address,uint256,uint256,uint256,uint256)");
const T_SELL = keccak256("CurveSell(address,address,uint256,uint256,uint256,uint256)");
const ZERO32 = "0x" + "0".repeat(64);

const PONS_FACTORY = (process.env.PONS_V2_FACTORY || "0x7ed598bcef8bd9edd8c97a195c6d13f40801ec7e").toLowerCase();
// contract addresses from Bitquery's Robinhood launchpad guide; override or extend with LAUNCHPADS_JSON
const PADS = [
  { key: "pons", name: "PONS", addrs: [PONS_FACTORY, "0xe33e9e479df8802cb0866d5d05258bec4cf62948"] },
  { key: "flap", name: "FLAP", addrs: ["0x26605f322f7ff986f381bb9a6e3f5dab0beaeb09"] },
  { key: "hoodfun", name: "HOOD.FUN", addrs: ["0x5fcc1df0dc020cf454e742e9a8ae2554c37a452c", "0x6a63d96ef77ae569fcb85934cf1bd1ec7fe9b33d"] },
  { key: "launchhood", name: "LAUNCHHOOD", addrs: ["0x62b33a039d289cbda50ebeb72fe4261449e61bcf"] },
  { key: "virtuals", name: "VIRTUALS", addrs: ["0xd4ccbfa37e2f35611b3042e4096ad7a3459bd007"] },
  { key: "klik", name: "KLIK", addrs: ["0x16cf6788b762ee8969744586ed16fc5705140dd7"] },
  { key: "doppler", name: "DOPPLER", addrs: ["0xeb7c034704ef8dcd2d32324c1545f62fb4ad0862", "0x22e99278308b393ea1260859b181ad7e78f5eeed", "0x4e3468951d49f2eea976ed0d6e75ffcb44a9a544"] },
  { key: "apestore", name: "APE.STORE", addrs: ["0x6e4910ea5a04376032f6564da9a9e4e88b7a87c1"] },
  { key: "bags", name: "BAGS", addrs: ["0xe8cc4431adf8b5a847c113ef0c6af9043219cb37"] },
  { key: "clanker", name: "CLANKER", addrs: ["0xd3f2cc1731b7fd17f28798835c2e02f0a1839a94"] },
  { key: "poolstrade", name: "POOLS.TRADE", addrs: ["0x0000ffffbe8efe702c8703ae3477ff5de3d319c0", "0x00004c4ccc709ef590f7c81102c0689f0263d4e9"] },
  { key: "trench", name: "TRENCH", addrs: ["0x77dc6f6361b7b99456fc3761ce5b7dda80d83f9d"] },
];
try { for (const p of JSON.parse(process.env.LAUNCHPADS_JSON || "[]")) { const ex = PADS.find((x) => x.key === p.key); if (ex) Object.assign(ex, p); else PADS.push(p); } } catch (e) { console.warn("LAUNCHPADS_JSON ignored:", e.message); }
const BY_ADDR = new Map();
for (const p of PADS) for (const a of p.addrs || []) BY_ADDR.set(String(a).toLowerCase(), p);

const CFG = {
  backfill: +process.env.LAUNCH_BACKFILL_BLOCKS || 60000,
  keep: +process.env.LAUNCH_KEEP || 300,
  txLookups: +process.env.LAUNCH_TX_LOOKUPS || 40,
  metaPerScan: +process.env.LAUNCH_META_PER_SCAN || 40,
  maxRange: +process.env.LAUNCH_MAX_RANGE || 20000,
  balancePerScan: +process.env.LAUNCH_BALANCES_PER_SCAN || 120,
};
const S = { seq: 0, announced: new Set(), last: 0, range: CFG.maxRange, launches: new Map(), curves: new Map(), times: new Map(), meta: new Map(), errors: 0, lastError: null, scannedAt: null };

const hexToInt = (h) => parseInt(h, 16);
const toHex = (n) => "0x" + n.toString(16);
const addrOf = (word) => "0x" + String(word).replace(/^0x/, "").slice(-40).toLowerCase();
const words = (log) => [...log.topics.slice(1), ...((log.data || "0x").slice(2).match(/.{64}/g) || []).map((w) => "0x" + w)];

async function getLogs(filter, from, to) {
  const out = [];
  let a = from;
  while (a <= to) {
    const b = Math.min(to, a + S.range - 1);
    try {
      const logs = await rpc("eth_getLogs", [{ ...filter, fromBlock: toHex(a), toBlock: toHex(b) }]);
      out.push(...logs);
      a = b + 1;
    } catch (e) {
      const msg = String(e.message || e);
      if (S.range > 200 && /range|limit|too many|exceed|size|10000|results|timeout|query/i.test(msg)) { S.range = Math.max(200, Math.floor(S.range / 2)); continue; }
      throw e;
    }
  }
  return out;
}

async function blockTime(n) {
  if (S.times.has(n)) return S.times.get(n);
  const b = await rpc("eth_getBlockByNumber", [toHex(n), false]);
  const t = b ? hexToInt(b.timestamp) * 1000 : Date.now();
  S.times.set(n, t);
  if (S.times.size > 3000) S.times.delete(S.times.keys().next().value);
  return t;
}

function decodeString(hex) {
  if (!hex || hex === "0x") return "";
  const h = hex.slice(2);
  try {
    if (h.length >= 128) { const len = parseInt(h.slice(64, 128), 16); if (len > 0 && len < 200) return Buffer.from(h.slice(128, 128 + len * 2), "hex").toString("utf8").replace(/\0/g, "").trim(); }
    return Buffer.from(h.slice(0, 64), "hex").toString("utf8").replace(/\0/g, "").trim(); // bytes32 style
  } catch (_) { return ""; }
}
async function erc20Meta(addr) {
  if (S.meta.has(addr)) return S.meta.get(addr);
  const call = (data) => rpc("eth_call", [{ to: addr, data }, "latest"]).catch(() => null);
  const [n, s, d, ts] = await Promise.all([call("0x06fdde03"), call("0x95d89b41"), call("0x313ce567"), call("0x18160ddd")]);
  const m = { name: decodeString(n).slice(0, 48), symbol: decodeString(s).slice(0, 16), decimals: d && d !== "0x" ? parseInt(d, 16) : 18, supply: ts && ts !== "0x" ? BigInt(ts) : 0n };
  if (m.symbol || m.name) S.meta.set(addr, m); // empty answer = try again on a later scan
  return m;
}

function addLaunch(token, pad, block, extra) {
  const id = token.toLowerCase();
  if (S.launches.has(id)) return;
  S.launches.set(id, { id, pad: pad.key, padName: pad.name, block, created: null, sym: null, name: null, seq: ++S.seq, ...extra });
  if (extra && extra.curve) S.curves.set(extra.curve.toLowerCase(), id);
  if (S.launches.size > CFG.keep) { const old = [...S.launches.values()].sort((a, b) => a.block - b.block)[0]; S.launches.delete(old.id); if (old.curve) S.curves.delete(old.curve); }
}

// each step keeps its own block cursor, so one failing query (e.g. an RPC that rejects big log filters) never blocks the others
const CUR = { launch: 0, mint: 0, trades: 0 };
function fail(step, e) { S.errors++; S.lastError = step + ": " + String(e.message || e).slice(0, 200); console.warn("launchpad scan", S.lastError); }

async function scanLaunches(latest) {
  const from = CUR.launch ? CUR.launch + 1 : Math.max(1, latest - CFG.backfill);
  if (from > latest) return;
  for (const log of await getLogs({ address: PONS_FACTORY, topics: [T_LAUNCH] }, from, latest)) {
    const w = words(log);
    if (w.length < 6) continue;
    addLaunch(addrOf(w[0]), PADS[0], hexToInt(log.blockNumber), { curve: addrOf(w[1]), deployer: addrOf(w[2]), pairToken: addrOf(w[3]), threshold: BigInt(w[5]), netQuote: 0n, lastPrice: null, trades: 0, tx: log.transactionHash });
  }
  CUR.launch = latest;
}
async function scanMints(latest) {
  const from = CUR.mint ? CUR.mint + 1 : Math.max(1, latest - CFG.backfill);
  if (from > latest) return;
  let lookups = 0;
  for (const log of await getLogs({ topics: [T_TRANSFER, ZERO32] }, from, latest)) {
    if (log.topics.length !== 3) continue; // ERC-721 mints carry a 4th topic
    const token = log.address.toLowerCase();
    if (S.launches.has(token) || BY_ADDR.has(token)) continue;
    let pad = BY_ADDR.get(addrOf(log.topics[2]));
    if (!pad && /(7777|8888)$/.test(token)) pad = PADS.find((p) => p.key === "flap");
    let deployer = null;
    if (!pad && lookups < CFG.txLookups) {
      lookups++;
      try { const tx = await rpc("eth_getTransactionByHash", [log.transactionHash]); if (tx && tx.to) { pad = BY_ADDR.get(tx.to.toLowerCase()); deployer = tx.from ? tx.from.toLowerCase() : null; } } catch (_) {}
    }
    if (pad) addLaunch(token, pad, hexToInt(log.blockNumber), { tx: log.transactionHash, deployer });
  }
  CUR.mint = latest;
}
function applyTrade(log) {
  const L = S.launches.get(S.curves.get(String(log.address).toLowerCase()));
  if (!L) return;
  const w = words(log);
  if (w.length < 4) return;
  const buy = log.topics[0] === T_BUY, q = BigInt(buy ? w[2] : w[3]), tok = BigInt(buy ? w[3] : w[2]);
  L.netQuote = (L.netQuote || 0n) + (buy ? q : -q);
  if (tok > 0n) L.lastPrice = { q, tok };
  L.trades = (L.trades || 0) + 1;
  S.tradeLogs = (S.tradeLogs || 0) + 1;
}
async function scanTrades(latest) {
  if (!S.curves.size) { CUR.trades = latest; return; }
  const from = CUR.trades ? CUR.trades + 1 : Math.max(1, latest - CFG.backfill);
  if (from > latest) return;
  // every curve trade on the chain by topic, then keep the ones from curves we know (Bitquery's recommended filter)
  let logs;
  try { logs = await getLogs({ topics: [[T_BUY, T_SELL]] }, from, latest); }
  catch (e) {
    logs = [];
    const curves = [...S.curves.keys()];
    for (let i = 0; i < curves.length; i += 20) logs.push(...(await getLogs({ address: curves.slice(i, i + 20), topics: [[T_BUY, T_SELL]] }, from, latest)));
  }
  for (const log of logs) applyTrade(log);
  CUR.trades = latest;
}
// the curve's live quote balance = quote raised so far (Bitquery: same figure as buys - sells). Works even for trades before our backfill window.
async function readCurveBalances() {
  const open = [...S.launches.values()].filter((l) => l.curve && l.threshold > 0n && !l.graduated).sort((a, b) => b.block - a.block).slice(0, CFG.balancePerScan);
  for (let i = 0; i < open.length; i += 8) {
    await Promise.all(open.slice(i, i + 8).map(async (l) => {
      try {
        const native = !l.pairToken || /^0x0{40}$/.test(l.pairToken);
        const r = native ? await rpc("eth_getBalance", [l.curve, "latest"])
          : await rpc("eth_call", [{ to: l.pairToken, data: "0x70a08231" + l.curve.slice(2).padStart(64, "0") }, "latest"]);
        if (r && r !== "0x") l.quoteBal = BigInt(r);
      } catch (_) {}
    }));
  }
}

async function scan() {
  const latest = hexToInt(await rpc("eth_blockNumber", []));
  S.lastError = null;
  try { await scanLaunches(latest); } catch (e) { fail("pons launches", e); }
  try { await scanMints(latest); } catch (e) { fail("launchpad mints", e); }
  try { await scanTrades(latest); } catch (e) { fail("curve trades", e); }
  try { await readCurveBalances(); } catch (e) { fail("curve balances", e); }
  S.last = latest;
  // names, symbols, supply, launch time for the newest tokens
  // tokens with no name yet, plus ones still showing their address because name()/symbol() came back empty (retried up to 12 scans)
  const todo = [...S.launches.values()].filter((l) => !l.sym || (l.noName && (l.nameTries || 0) < 12)).sort((a, b) => b.block - a.block).slice(0, CFG.metaPerScan);
  for (let i = 0; i < todo.length; i += 6) {
    await Promise.all(todo.slice(i, i + 6).map(async (l) => {
      try {
        const m = await erc20Meta(l.id);
        l.nameTries = (l.nameTries || 0) + 1;
        l.noName = !m.symbol && !m.name;
        l.sym = m.symbol || m.name || l.id.slice(0, 6) + "…" + l.id.slice(-4); l.name = m.name || m.symbol || ""; l.decimals = m.decimals; if (m.supply) l.supply = m.supply;
        if (!l.created) l.created = new Date(await blockTime(l.block)).toISOString();
        if (l.pairToken && !l.pairSym) { const pm = /^0x0{40}$/.test(l.pairToken) ? { symbol: "ETH", decimals: 18 } : await erc20Meta(l.pairToken); l.pairSym = pm.symbol || "?"; l.pairDec = pm.decimals == null ? 18 : pm.decimals; }
      } catch (_) {}
    }));
  }
  S.scannedAt = new Date().toISOString();
  for (const l of S.launches.values()) {
    if (!l.sym || !l.created || S.announced.has(l.id)) continue;
    S.announced.add(l.id);
    for (const fn of listeners) { try { fn(l); } catch (e) { console.warn("onLaunch listener:", e.message); } }
  }
}
// deployer for tokens found through a mint log without a tx lookup (filled lazily by the threat scanner)
async function deployerOf(addr) {
  const l = S.launches.get(String(addr).toLowerCase());
  if (!l) return null;
  if (l.deployer) return l.deployer;
  if (!l.tx) return null;
  try { const tx = await rpc("eth_getTransactionByHash", [l.tx]); if (tx && tx.from) l.deployer = tx.from.toLowerCase(); } catch (_) {}
  return l.deployer || null;
}
const get = (addr) => S.launches.get(String(addr || "").toLowerCase()) || null;
const all = () => [...S.launches.values()];
const infra = () => { const s = new Set(BY_ADDR.keys()); for (const c of S.curves.keys()) s.add(c); return s; };

// usd value of one unit of the pair token (ETH/WETH -> ethUsd, stables -> 1)
// ethUsd: number, or a function (address, symbol) -> usd price from DexPaprika pools (covers stock tokens like SPCX/QQQ)
function quoteUsd(l, ethUsd) {
  const s = String(l.pairSym || "").toUpperCase(), fn = typeof ethUsd === "function" ? ethUsd : null;
  if (!l.pairToken || /^0x0{40}$/.test(l.pairToken) || s === "WETH" || s === "ETH") return (fn ? fn(null, "WETH") : ethUsd) || 0;
  if (["USDG", "USDC", "USDT", "DAI", "USDE"].includes(s)) return 1;
  return (fn && fn(l.pairToken, s)) || 0;
}
function list(ethUsd, onDex) {
  return [...S.launches.values()].filter((l) => l.sym && l.created).map((l) => {
    const graduated = onDex && onDex.has(l.id);
    if (graduated) l.graduated = true;
    const qd = 10 ** (l.pairDec == null ? 18 : l.pairDec), td = 10 ** (l.decimals || 18);
    let mc = null, progress = null, raised = null, target = null;
    const usd = quoteUsd(l, ethUsd);
    if (l.lastPrice && l.supply && usd) mc = (Number(l.lastPrice.q) / qd) / (Number(l.lastPrice.tok) / td) * usd * (Number(l.supply) / td);
    if (l.threshold && l.threshold > 0n) {
      const net = l.netQuote > 0n ? l.netQuote : 0n, bal = l.quoteBal || 0n;
      const got = bal > net ? bal : net; // curve balance, or buys - sells if the curve does not hold the quote itself
      raised = Number(got) / qd; target = Number(l.threshold) / qd;
      progress = Math.max(0, Math.min(1, raised / target));
    }
    return { id: l.id, sym: l.sym, name: l.name, noName: !!l.noName, created: l.created, src: l.pad, srcName: l.padName, status: graduated ? "dex" : "bonding", progress, raised, target, mc, liq: null, pair: l.pairSym || "", trades: l.trades || 0 };
  });
}
// one token's raw scanner state, for checking against ponsfamily.com
const debug = (addr) => { const l = S.launches.get(String(addr).toLowerCase()); if (!l) return null;
  const big = (v) => (v == null ? null : v.toString());
  return { id: l.id, sym: l.sym, pad: l.pad, block: l.block, curve: l.curve || null, pairToken: l.pairToken || null, pairSym: l.pairSym || null, threshold: big(l.threshold), curveQuoteBalance: big(l.quoteBal), netQuoteFromTrades: big(l.netQuote), trades: l.trades || 0, lastPrice: l.lastPrice ? { quote: big(l.lastPrice.q), tokens: big(l.lastPrice.tok) } : null, scanCursors: CUR }; };
const known = (addr) => { const l = S.launches.get(String(addr).toLowerCase()); return l ? { src: l.pad, srcName: l.padName } : null; };
const status = () => ({ cursors: CUR, tradeLogs: S.tradeLogs || 0, withBalance: [...S.launches.values()].filter((l) => l.quoteBal > 0n).length, last: S.last, range: S.range, tracked: S.launches.size, curves: S.curves.size, errors: S.errors, lastError: S.lastError, scannedAt: S.scannedAt, pads: PADS.map((p) => p.key) });

const tokenMeta = async (addr) => { const m = await erc20Meta(String(addr).toLowerCase()); return { address: String(addr).toLowerCase(), symbol: m.symbol, name: m.name, decimals: m.decimals }; };
module.exports = { scan, list, known, status, debug, tokenMeta, PADS, onLaunch, get, all, infra, deployerOf, erc20Meta };
