// THREAT SCANNER — heuristic danger signals for one token, from real on-chain data.
// Every signal carries its evidence. Signals are not verdicts: the UI and the AI say so.
// Sources: Transfer logs + balanceOf (RPC), launch record (launchpads.js), pools (DexPaprika), swap test (Uniswap quoters).
const { rpc, keccak256, CFG: SWAP } = require("./swaptest");

const T_TRANSFER = keccak256("Transfer(address,address,uint256)");
const ZERO = "0x0000000000000000000000000000000000000000";
const DEAD = "0x000000000000000000000000000000000000dead";
const toHex = (n) => "0x" + n.toString(16);
const hexToInt = (h) => parseInt(h, 16);
const addrOf = (w) => "0x" + String(w).replace(/^0x/, "").slice(-40).toLowerCase();
const short = (a) => (a ? a.slice(0, 6) + "…" + a.slice(-4) : "?");
const pct = (x) => (x * 100).toFixed(x < 0.1 ? 1 : 0) + "%";

const CFG = {
  maxBlocks: +process.env.THREAT_MAX_BLOCKS || 1500000, // ~1.7 days at 100 ms blocks
  maxLogs: +process.env.THREAT_MAX_LOGS || 40000,
  candidates: +process.env.THREAT_BALANCE_CANDIDATES || 40,
  ttlMs: (+process.env.THREAT_CACHE_SECONDS || 600) * 1000,
  swapUsd: +process.env.THREAT_SWAP_USD || 50,
};
const BRANDS = (process.env.IMPERSONATION_WATCHLIST || "ROBINHOOD,HOOD,PONS,FLAP,UNISWAP,COINBASE,BASE,ARBITRUM,OPENAI,SPACEX,NVIDIA,TESLA,APPLE,ELON,TRUMP,PEPE,DOGE,SHIB,BONK,WIF").split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
const CANON_GLYPH = { "0": "O", "1": "I", "3": "E", "4": "A", "5": "S", "$": "S" };
const canon = (x) => String(x || "").toUpperCase().split("").map((c) => CANON_GLYPH[c] || c).join("").replace(/[^A-Z]/g, "").replace(/(OFFICIAL|REAL|INU|AI|V2|V3|X|2|3)$/, "");

let range = 50000;
async function getLogs(filter, from, to, cap) {
  const out = [];
  let a = from;
  while (a <= to) {
    const b = Math.min(to, a + range - 1);
    try {
      const logs = await rpc("eth_getLogs", [{ ...filter, fromBlock: toHex(a), toBlock: toHex(b) }]);
      out.push(...logs);
      if (out.length >= cap) return { logs: out, truncated: true };
      a = b + 1;
    } catch (e) {
      const msg = String(e.message || e);
      if (range > 500 && /range|limit|too many|exceed|size|10000|results|timeout|query/i.test(msg)) { range = Math.max(500, Math.floor(range / 2)); continue; }
      throw e;
    }
  }
  return { logs: out, truncated: false };
}
const balanceOf = async (token, who) => { try { const r = await rpc("eth_call", [{ to: token, data: "0x70a08231" + who.slice(2).padStart(64, "0") }, "latest"]); return r && r !== "0x" ? BigInt(r) : 0n; } catch (_) { return null; } };
const isContract = async (a) => { try { const c = await rpc("eth_getCode", [a, "latest"]); return !!c && c !== "0x"; } catch (_) { return false; } };
const totalSupply = async (token) => { try { const r = await rpc("eth_call", [{ to: token, data: "0x18160ddd" }, "latest"]); return r && r !== "0x" ? BigInt(r) : 0n; } catch (_) { return 0n; } };

/**
 * deps: { launchpads, lookupToken(addr) -> {pools}, swapTestToken(addr, usd), pools() -> snapshot pools, stockSyms:Set, official:{ca,ticker} }
 */
function createThreat(deps) {
  const cache = new Map();

  async function scan(addrIn, { force = false } = {}) {
    const addr = String(addrIn).toLowerCase();
    const hit = cache.get(addr);
    if (!force && hit && Date.now() - hit.at < CFG.ttlMs) return hit.data;

    const L = deps.launchpads.get(addr);
    const signals = [], checks = [], notEvaluated = [];
    const add = (id, label, weight, evidence) => signals.push({ id, label, weight, evidence });
    const ok = (label) => checks.push(label);

    // ---------- identity ----------
    let meta = { symbol: L && L.sym, name: L && L.name, decimals: 18 };
    try { const m = await deps.launchpads.erc20Meta(addr); meta = { symbol: m.symbol || meta.symbol, name: m.name || meta.name, decimals: m.decimals == null ? 18 : m.decimals }; } catch (_) {}
    const supply = await totalSupply(addr);
    let dex = { pools: [] };
    try { dex = await deps.lookupToken(addr); } catch (_) {}
    const pools = (dex.pools || []).filter((p) => p.a.id.toLowerCase() === addr || p.b.id.toLowerCase() === addr);
    const launchpad = L ? L.pad : pools.length ? "dex" : null;

    // ---------- holders, creator, bundle (Transfer logs) ----------
    let latest = 0;
    try { latest = hexToInt(await rpc("eth_blockNumber", [])); } catch (e) { notEvaluated.push("Everything on-chain (RPC unreachable)"); }
    const poolBlocks = pools.map((p) => p.createdBlock).filter((x) => x != null);
    const startBlock = L ? L.block : poolBlocks.length ? Math.min(...poolBlocks) : latest ? latest - 200000 : 0;
    const metrics = { supply: supply.toString(), decimals: meta.decimals, launchBlock: startBlock || null };
    let deployer = L ? await deps.launchpads.deployerOf(addr) : null;

    if (latest && supply > 0n) {
      const from = Math.max(1, Math.max(startBlock, latest - CFG.maxBlocks));
      try {
        const { logs, truncated } = await getLogs({ address: addr, topics: [T_TRANSFER] }, from, latest, CFG.maxLogs);
        metrics.transfers = logs.length; metrics.partialHistory = truncated || from > startBlock;
        const infra = deps.launchpads.infra();
        for (const a of [ZERO, DEAD, addr, String(SWAP.poolManager).toLowerCase()]) infra.add(a);
        if (L && L.curve) infra.add(L.curve);
        for (const p of pools) if (/^0x[0-9a-f]{40}$/i.test(p.id)) infra.add(p.id.toLowerCase());
        const net = new Map(), running = new Map(), peak = new Map(), early = new Set();
        let firstMint = null;
        for (const lg of logs) {
          if (lg.topics.length !== 3) continue;
          const f = addrOf(lg.topics[1]), t = addrOf(lg.topics[2]), v = BigInt(lg.data && lg.data !== "0x" ? lg.data : "0x0"), bn = hexToInt(lg.blockNumber);
          if (f === ZERO && !firstMint) firstMint = lg;
          net.set(t, (net.get(t) || 0n) + v); net.set(f, (net.get(f) || 0n) - v);
          const rt = (running.get(t) || 0n) + v; running.set(t, rt); if (rt > (peak.get(t) || 0n)) peak.set(t, rt);
          running.set(f, (running.get(f) || 0n) - v);
          if (startBlock && bn <= startBlock + 2 && infra.has(f) && !infra.has(t)) early.add(t);
        }
        if (!deployer && firstMint) { try { const tx = await rpc("eth_getTransactionByHash", [firstMint.transactionHash]); if (tx && tx.from) deployer = tx.from.toLowerCase(); } catch (_) {} }
        if (deployer) early.delete(deployer);
        metrics.deployer = deployer;

        // current balances of the biggest receivers (exact, via balanceOf), skipping contracts and infrastructure
        const cand = [...net.entries()].filter(([a, v]) => v > 0n && !infra.has(a)).sort((x, y) => (y[1] > x[1] ? 1 : y[1] < x[1] ? -1 : 0)).slice(0, CFG.candidates).map(([a]) => a);
        if (deployer && !cand.includes(deployer)) cand.push(deployer);
        const bal = new Map(), contracts = new Set();
        for (let i = 0; i < cand.length; i += 8) await Promise.all(cand.slice(i, i + 8).map(async (a) => { const b = await balanceOf(addr, a); if (b != null) bal.set(a, b); if (await isContract(a)) contracts.add(a); }));
        const eoa = [...bal.entries()].filter(([a, b]) => b > 0n && !contracts.has(a)).sort((x, y) => (y[1] > x[1] ? 1 : -1));
        const share = (b) => Number((b * 1000000n) / supply) / 1e6;
        metrics.holders = [...net.values()].filter((v) => v > 0n).length;
        metrics.top10Pct = share(eoa.slice(0, 10).reduce((s, [, b]) => s + b, 0n));
        metrics.top = eoa.slice(0, 10).map(([a, b]) => ({ address: a, pct: +(share(b) * 100).toFixed(2), creator: a === deployer }));
        metrics.bundle = early.size;

        if (deployer) {
          const now = bal.get(deployer) || 0n, pk = peak.get(deployer) || 0n;
          metrics.creatorPct = share(now);
          metrics.creatorExitPct = pk > 0n ? Math.max(0, 1 - Number((now * 1000000n) / pk) / 1e6) : 0;
          if (metrics.creatorPct > 0.1) add("CREATOR_CONCENTRATION", "CREATOR CONCENTRATION", 20, `Creator wallet ${short(deployer)} holds ${pct(metrics.creatorPct)} of supply.`);
          else ok(`Creator holds ${pct(metrics.creatorPct)} of supply`);
          if (pk > 0n && metrics.creatorExitPct >= 0.5) add("CREATOR_EXIT", "CREATOR EXIT", 25, `Creator ${short(deployer)} has moved out ${pct(metrics.creatorExitPct)} of their peak position.`);
          else if (pk > 0n) ok("Creator has not exited their position");
          const serial = deps.launchpads.all().filter((l) => l.deployer === deployer && l.id !== addr).length;
          metrics.creatorLaunches = serial;
          if (serial >= 3) add("SERIAL_LAUNCHER", "SERIAL LAUNCHER", 15, `Same creator launched ${serial} other tokens while OBSERV was watching.`);
        } else notEvaluated.push("Creator checks (creator wallet not identified)");

        if (metrics.top10Pct > 0.45) add("TOP10_CONCENTRATION", "TOP-10 CONCENTRATION", 15, `Top 10 holder wallets control ${pct(metrics.top10Pct)} of supply (contracts and pools excluded).`);
        else ok(`Top 10 wallets hold ${pct(metrics.top10Pct)} of supply`);
        if (startBlock) {
          if (early.size >= 5) add("BUNDLED_GENESIS", "BUNDLED GENESIS", 20, `${early.size} wallets received tokens within 2 blocks of launch.`);
          else ok(`${early.size} early buyers in the first 2 blocks`);
        }
        if (metrics.partialHistory) notEvaluated.push("Full transfer history (token older than the scan window, holder count is a lower bound)");
      } catch (e) {
        notEvaluated.push("Holder & creator checks (RPC log query failed: " + String(e.message || e).slice(0, 80) + ")");
      }
    }

    // ---------- name / ticker ----------
    const c = canon(meta.symbol), cn = canon(meta.name);
    const official = deps.official && deps.official.ca ? deps.official.ca.toLowerCase() : "";
    const offTick = deps.official ? canon(deps.official.ticker) : "";
    const realStock = deps.stockOfficial ? deps.stockOfficial() : new Map(); // sym -> deepest (real) stock token address
    const isRealStock = [...realStock.values()].includes(addr);
    const stockHit = isRealStock ? null : [...deps.stockSyms].find((s) => c === s || (c.startsWith(s) && c.length <= s.length + 4));
    const brandHit = isRealStock || addr === official ? null : BRANDS.find((b) => c === b || cn === b || (b.length >= 4 && (c.startsWith(b) || cn.startsWith(b))));
    if (official && addr !== official && offTick && (c === offTick || cn === offTick)) add("TICKER_IMPERSONATION", "IMPERSONATES THIS PROJECT", 30, `Uses the ${deps.official.ticker} name but is NOT the official contract.`);
    else if (stockHit) add("TICKER_IMPERSONATION", "TICKER IMPERSONATION", 15, `Ticker ${meta.symbol} mimics the ${stockHit} stock token.`);
    else if (brandHit) add("TICKER_IMPERSONATION", "TICKER IMPERSONATION", 10, `Name/ticker ${meta.symbol} borrows the ${brandHit} brand.`);
    else {
      // a much deeper token elsewhere on the chain uses the same ticker
      let R = 0; for (const p of pools) if (p.liq >= 1000) R += p.liq / 2;
      const deeper = new Map();
      for (const p of deps.pools()) for (const t of [p.a, p.b]) if (t.id.toLowerCase() !== addr && canon(t.sym) === c && c.length >= 2) deeper.set(t.id, (deeper.get(t.id) || 0) + p.liq / 2);
      const best = [...deeper.entries()].sort((x, y) => y[1] - x[1])[0];
      if (best && best[1] > Math.max(1, R) * 3) add("CLONE_TICKER", "CLONE TICKER", 15, `Same ticker as a deeper token ${short(best[0])} with ~$${Math.round(best[1] * 2).toLocaleString("en-US")} liquidity.`);
      else ok("No ticker impersonation detected");
    }

    // ---------- market: real volume, exit depth, swap test ----------
    if (pools.length) {
      let vol = 0, real = 0, R = 0;
      for (const p of pools) { vol += p.vol; real += p.liq < 1000 ? 0 : Math.min(p.vol, p.liq * 10); if (p.liq >= 1000) R += p.liq / 2; }
      metrics.liquidityUsd = Math.round(R * 2); metrics.volume24hUsd = Math.round(vol);
      metrics.realVolumePct = vol ? Math.round((real / vol) * 100) : 100;
      metrics.sellable5Usd = Math.round((R * 0.05) / 0.95);
      if (vol && real / vol < 0.5) add("FAKE_VOLUME", "INFLATED VOLUME", 10, `Only ${metrics.realVolumePct}% of 24h volume is plausible for its liquidity.`);
      if (metrics.sellable5Usd < 2000) add("THIN_EXIT", "THIN EXIT", 10, `Only ~$${metrics.sellable5Usd.toLocaleString("en-US")} can be sold before the price drops 5%.`);
      else ok(`~$${metrics.sellable5Usd.toLocaleString("en-US")} sellable before -5%`);
      try {
        const st = await deps.swapTestToken(addr, CFG.swapUsd);
        const b = st && st.best;
        if (b) {
          metrics.swapTest = { verdict: b.verdict, lossPct: +b.lossPct.toFixed(2), hookTaxPct: +(b.hookTaxPct || 0).toFixed(2), dex: b.dex, usd: CFG.swapUsd, hook: b.hook };
          if (b.verdict === "NO EXIT" || b.verdict === "HOOK TRAP") add("HONEYPOT", "SELL BLOCKED", 40, `Swap test: a $${CFG.swapUsd} round trip returned only ${(100 - b.lossPct).toFixed(1)}% (${b.verdict}).`);
          else if (b.verdict === "HOOK TAX") add("HOOK_TAX", "HOOK TAX", 15, `Swap test: the pool's v4 hook takes ~${b.hookTaxPct.toFixed(1)}% beyond normal fees.`);
          else ok(`Swap test: sell path executes (${b.lossPct.toFixed(1)}% round-trip cost)`);
          if (b.hook && b.hook.hooked && (b.hook.canBlockExit || b.hook.canTaxSwaps) && !signals.some((s) => s.id === "HONEYPOT" || s.id === "HOOK_TAX")) add("CUSTOM_HOOK", "CUSTOM HOOK LOGIC", 10, `Pool runs a Uniswap v4 hook with ${b.hook.flags.join(", ")} permissions.`);
        } else if (st && st.results && st.results.length) {
          const allFail = st.results.every((r) => r.error);
          if (allFail) notEvaluated.push("Swap test (no quote: " + String(st.results[0].error).slice(0, 60) + ")");
        } else notEvaluated.push("Swap test (no pool deep enough)");
      } catch (e) { notEvaluated.push("Swap test (" + String(e.message || e).slice(0, 60) + ")"); }
    } else {
      notEvaluated.push(L && L.pad ? "DEX checks (still on the launchpad curve, no DEX pool yet)" : "DEX checks (no DEX pool found)");
    }
    if (L && L.threshold > 0n) {
      const qd = 10 ** (L.pairDec == null ? 18 : L.pairDec), raised = Number(L.quoteBal || (L.netQuote > 0n ? L.netQuote : 0n)) / qd, target = Number(L.threshold) / qd;
      metrics.bonding = { raised, target, progress: target ? Math.min(1, raised / target) : null, pair: L.pairSym || "ETH" };
    }

    const score = Math.min(100, signals.reduce((s, x) => s + x.weight, 0));
    const level = score >= 75 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 25 ? "ELEVATED" : "LOW";
    const data = {
      token: addr, symbol: meta.symbol || null, name: meta.name || null, launchpad, launchpadName: L ? L.padName : pools.length ? "DEX" : null,
      created: L ? L.created : null, block: startBlock || null, launchTx: L ? L.tx || null : null,
      score, level, signals: signals.sort((a, b) => b.weight - a.weight), checks, notEvaluated, metrics,
      disclaimer: "Heuristic signals from on-chain data. Not a verdict, not an accusation, not advice. A low score does not mean safe.",
      scannedAt: new Date().toISOString(),
    };
    if (latest) cache.set(addr, { at: Date.now(), data }); // never cache a scan made while the RPC was down
    if (cache.size > 2000) cache.delete(cache.keys().next().value);
    return data;
  }

  const cached = (addr) => { const h = cache.get(String(addr).toLowerCase()); return h ? h.data : null; };
  const recent = () => [...cache.values()].map((h) => h.data);
  return { scan, cached, recent };
}

module.exports = { createThreat };
