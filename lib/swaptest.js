// SWAP TEST: round-trip simulation on Robinhood Chain through the real Uniswap quoters (eth_call, read-only).
// Buy the token with a quote asset worth $X, sell everything back, compare. The loss includes LP fees,
// price impact and whatever a v4 hook takes. Every call is returned so anyone can reproduce it.
// Uniswap deployments for chain 4663: github.com/Uniswap/contracts/blob/main/deployments/4663.md

// ---------- keccak-256 (Ethereum flavour), no dependencies ----------
const RC = [1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n, 0x8an, 0x88n, 0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const M64 = (1n << 64n) - 1n;
const rotl = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64);
function keccakF(s) {
  for (let r = 0; r < 24; r++) {
    const C = [0, 1, 2, 3, 4].map((x) => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
    for (let x = 0; x < 5; x++) { const d = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1); for (let y = 0; y < 25; y += 5) s[x + y] ^= d; }
    const B = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], ROT[x + 5 * y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x + 5 * y] = B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & M64 & B[((x + 2) % 5) + 5 * y]);
    s[0] ^= RC[r];
  }
}
function keccak256(input) {
  const bytes = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
  const rate = 136, padLen = rate - (bytes.length % rate), msg = Buffer.concat([bytes, Buffer.alloc(padLen)]);
  msg[bytes.length] ^= 0x01; msg[msg.length - 1] ^= 0x80;
  const s = new Array(25).fill(0n);
  for (let off = 0; off < msg.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) { let v = 0n; for (let b = 7; b >= 0; b--) v = (v << 8n) | BigInt(msg[off + i * 8 + b]); s[i] ^= v; }
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) for (let b = 0; b < 8; b++) out[i * 8 + b] = Number((s[i] >> BigInt(8 * b)) & 0xffn);
  return "0x" + out.toString("hex");
}
const selector = (sig) => keccak256(sig).slice(0, 10);

// ---------- tiny ABI helpers ----------
const word = (v) => { let b = BigInt(v); if (b < 0n) b = (1n << 256n) + b; return b.toString(16).padStart(64, "0"); };
const addr = (a) => String(a || "0x0").toLowerCase().replace(/^0x/, "").padStart(64, "0");
const bool = (b) => word(b ? 1 : 0);
const toBig = (hex) => BigInt(hex && hex !== "0x" ? hex : "0x0");
const isAddr = (a) => /^0x[0-9a-fA-F]{40}$/.test(String(a || ""));
const ZERO = "0x0000000000000000000000000000000000000000";

const CFG = {
  rpc: process.env.RPC_URL || "https://rpc.mainnet.chain.robinhood.com",
  poolManager: process.env.V4_POOL_MANAGER || "0x8366a39cc670b4001a1121b8f6a443a643e40951",
  v4Quoter: process.env.V4_QUOTER || "0x8dc178efb8111bb0973dd9d722ebeff267c98f94",
  v3Quoter: process.env.V3_QUOTER || "0x33e885ed0ec9bf04ecfb19341582aadcb4c8a9e7",
  v2Router: process.env.V2_ROUTER || "0x89e5db8b5aa49aa85ac63f691524311aeb649eba",
};
const SIG = {
  initialize: "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)",
  v4quote: "quoteExactInputSingle(((address,address,uint24,int24,address),bool,uint128,bytes))",
  v3quote: "quoteExactInputSingle((address,address,uint256,uint24,uint160))",
  v2amounts: "getAmountsOut(uint256,address[])",
  decimals: "decimals()",
};

let rpcId = 1;
async function rpc(method, params) {
  const res = await fetch(CFG.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method, params }), signal: AbortSignal.timeout(15000) });
  const j = await res.json();
  if (j.error) { const e = new Error(j.error.message || "rpc error"); e.data = j.error.data; throw e; }
  return j.result;
}
const ethCall = (to, data, block = "latest") => rpc("eth_call", [{ to, data }, block]);

const decCache = new Map();
async function decimals(token) {
  if (!isAddr(token) || token.toLowerCase() === ZERO) return 18;
  const k = token.toLowerCase();
  if (decCache.has(k)) return decCache.get(k);
  let d = 18;
  try { d = Number(toBig(await ethCall(token, selector(SIG.decimals)))); } catch { /* keep 18 */ }
  decCache.set(k, d);
  return d;
}

// ---------- v4 hook permissions live in the low 14 bits of the hook address ----------
const HOOK_BITS = [
  [13, "beforeInitialize"], [12, "afterInitialize"], [11, "beforeAddLiquidity"], [10, "afterAddLiquidity"],
  [9, "beforeRemoveLiquidity"], [8, "afterRemoveLiquidity"], [7, "beforeSwap"], [6, "afterSwap"],
  [5, "beforeDonate"], [4, "afterDonate"], [3, "beforeSwapReturnsDelta"], [2, "afterSwapReturnsDelta"],
  [1, "afterAddLiquidityReturnsDelta"], [0, "afterRemoveLiquidityReturnsDelta"],
];
function hookFlags(hooks) {
  if (!isAddr(hooks) || hooks.toLowerCase() === ZERO) return { hooked: false, flags: [], canTaxSwaps: false, canBlockExit: false };
  const low = Number(BigInt(hooks) & 0x3fffn);
  const flags = HOOK_BITS.filter(([b]) => low & (1 << b)).map(([, n]) => n);
  return {
    hooked: true, flags,
    canTaxSwaps: flags.includes("beforeSwapReturnsDelta") || flags.includes("afterSwapReturnsDelta"),
    canBlockExit: flags.includes("beforeSwap") || flags.includes("beforeRemoveLiquidity"),
  };
}

// ---------- v4 PoolKey from the PoolManager's Initialize event ----------
const keyCache = new Map();
async function v4PoolKey(poolId, createdBlock) {
  if (keyCache.has(poolId)) return keyCache.get(poolId);
  const topic0 = keccak256(SIG.initialize);
  const ranges = createdBlock != null ? [[createdBlock, createdBlock + 2]] : [];
  ranges.push(["0x0", "latest"]);
  let log = null;
  for (const [from, to] of ranges) {
    try {
      const f = typeof from === "number" ? "0x" + from.toString(16) : from, t = typeof to === "number" ? "0x" + to.toString(16) : to;
      const logs = await rpc("eth_getLogs", [{ address: CFG.poolManager, topics: [topic0, poolId], fromBlock: f, toBlock: t }]);
      if (logs && logs.length) { log = logs[0]; break; }
    } catch { /* wide ranges may be refused by the RPC; try the next */ }
  }
  if (!log) throw new Error("Initialize event for this pool not found");
  const d = log.data.replace(/^0x/, "");
  const w = (i) => "0x" + d.slice(i * 64, i * 64 + 64);
  const feeRaw = Number(toBig(w(0)) & 0xffffffn);
  let ts = Number(toBig(w(1)) & 0xffffffn); if (ts & 0x800000) ts -= 0x1000000;
  const key = {
    currency0: "0x" + log.topics[2].slice(-40), currency1: "0x" + log.topics[3].slice(-40),
    fee: feeRaw, tickSpacing: ts, hooks: "0x" + w(2).slice(-40), dynamicFee: feeRaw === 0x800000, block: Number(toBig(log.blockNumber)),
  };
  keyCache.set(poolId, key);
  return key;
}

// ---------- quoters ----------
function v4QuoteData(key, zeroForOne, amount) {
  // tuple param is dynamic (holds bytes): head offset, then the tuple, then the empty bytes
  return selector(SIG.v4quote) + word(0x20) + addr(key.currency0) + addr(key.currency1) + word(key.fee) + word(key.tickSpacing) + addr(key.hooks) + bool(zeroForOne) + word(amount) + word(0x100) + word(0);
}
async function v4Quote(key, zeroForOne, amount) {
  const data = v4QuoteData(key, zeroForOne, amount);
  const out = await ethCall(CFG.v4Quoter, data);
  return { out: toBig("0x" + out.slice(2, 66)), call: { to: CFG.v4Quoter, data } };
}
async function v3Quote(tokenIn, tokenOut, fee, amount) {
  const data = selector(SIG.v3quote) + addr(tokenIn) + addr(tokenOut) + word(amount) + word(fee) + word(0);
  const out = await ethCall(CFG.v3Quoter, data);
  return { out: toBig("0x" + out.slice(2, 66)), call: { to: CFG.v3Quoter, data } };
}
async function v2Quote(tokenIn, tokenOut, amount) {
  const data = selector(SIG.v2amounts) + word(amount) + word(0x40) + word(2) + addr(tokenIn) + addr(tokenOut);
  const out = (await ethCall(CFG.v2Router, data)).replace(/^0x/, "");
  // returns uint256[]: offset, length, a0, a1
  return { out: toBig("0x" + out.slice(64 * 3, 64 * 4)), call: { to: CFG.v2Router, data } };
}
const v3Fee = (f) => { const x = Number(f); if (!isFinite(x) || x <= 0) return 3000; if (x < 1) return Math.round(x * 1e6); if (x < 100) return Math.round(x * 1e4); return Math.round(x); };

/**
 * Round trip for one pool: spend `usd` of the quote side buying `token`, then sell all of it back.
 * pool = normalized DexPaprika pool {id, dex, a, b, fee, createdBlock}; token = subject token id; quoteUsd = USD price of the quote asset.
 */
async function roundTrip(pool, tokenId, usd, quoteUsd) {
  const tokSide = pool.a.id.toLowerCase() === tokenId.toLowerCase() ? pool.a : pool.b, quoteSide = tokSide === pool.a ? pool.b : pool.a;
  const kind = /v4/i.test(pool.dex) ? "v4" : /v3/i.test(pool.dex) ? "v3" : "v2";
  const res = { pool: pool.id, dex: pool.dex, kind, token: tokSide.sym, quote: quoteSide.sym, usd, calls: [] };
  const qDec = await decimals(quoteSide.id);
  const amountIn = BigInt(Math.max(1, Math.floor((usd / Math.max(quoteUsd, 1e-9)) * 10 ** Math.min(qDec, 18)))) * 10n ** BigInt(Math.max(0, qDec - 18));
  res.amountIn = amountIn.toString();
  if (kind === "v4") {
    const key = await v4PoolKey(pool.id, pool.createdBlock);
    Object.assign(res, { key, hook: hookFlags(key.hooks) });
    const quoteAddr = isAddr(quoteSide.id) ? quoteSide.id.toLowerCase() : ZERO, qIs0 = key.currency0.toLowerCase() === quoteAddr;
    const buy = await v4Quote(key, qIs0, amountIn); res.calls.push({ step: "buy", ...buy.call });
    const sell = await v4Quote(key, !qIs0, buy.out); res.calls.push({ step: "sell back", ...sell.call });
    res.tokenOut = buy.out.toString(); res.back = sell.out.toString();
    res.lpFeePct = key.dynamicFee ? null : key.fee / 1e4;
  } else if (kind === "v3") {
    const fee = v3Fee(pool.fee);
    const buy = await v3Quote(quoteSide.id, tokSide.id, fee, amountIn); res.calls.push({ step: "buy", ...buy.call });
    const sell = await v3Quote(tokSide.id, quoteSide.id, fee, buy.out); res.calls.push({ step: "sell back", ...sell.call });
    res.tokenOut = buy.out.toString(); res.back = sell.out.toString(); res.lpFeePct = fee / 1e4; res.hook = hookFlags(ZERO);
  } else {
    const buy = await v2Quote(quoteSide.id, tokSide.id, amountIn); res.calls.push({ step: "buy", ...buy.call });
    const sell = await v2Quote(tokSide.id, quoteSide.id, buy.out); res.calls.push({ step: "sell back", ...sell.call });
    res.tokenOut = buy.out.toString(); res.back = sell.out.toString(); res.lpFeePct = 0.3; res.hook = hookFlags(ZERO);
  }
  const back = Number(BigInt(res.back) * 1000000n / (amountIn || 1n)) / 1e6;
  res.backUsd = usd * back;
  res.lossPct = Math.max(0, (1 - back) * 100);
  // what plain AMM math expects for this size: two LP fees + two-way impact on the pool's reserves
  const lp = res.lpFeePct != null ? res.lpFeePct : 0.3, R = Math.max(1, pool.liq / 2), impact = (usd / (R + usd)) * 2 * 100;
  res.expectedPct = 2 * lp + impact;
  res.hookTaxPct = res.hook && res.hook.hooked ? Math.max(0, res.lossPct - res.expectedPct) : 0;
  res.verdict = res.lossPct >= 50 ? "HOOK TRAP" : res.hookTaxPct >= 10 ? "HOOK TAX" : res.lossPct >= 10 ? "EXPENSIVE" : "CLEAN";
  if (!res.hook.hooked && res.lossPct >= 50) res.verdict = "NO EXIT";
  res.block = "latest";
  return res;
}

module.exports = { keccak256, selector, hookFlags, v4QuoteData, v4PoolKey, roundTrip, v3Fee, CFG, SIG, rpc };
