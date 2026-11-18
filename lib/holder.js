// OBSERV Holder Pass — token-gated perks with a free sign-in signature.
// The wallet signs a plain-text message (EIP-191 personal_sign). No transaction, no approval, no gas.
// The server recovers the signer, reads the token balance over RPC, and issues a short-lived HMAC pass.
// Zero dependencies: secp256k1 public-key recovery in BigInt, keccak256 from swaptest.js.
const crypto = require("crypto");
const { keccak256, rpc } = require("./swaptest");

// ---------- secp256k1 recovery ----------
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m = P) => ((a % m) + m) % m;
function powm(b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
const inv = (a, m = P) => powm(a, m - 2n, m);
// Jacobian coordinates for speed
function jDouble([X, Y, Z]) {
  if (Y === 0n) return [0n, 0n, 0n];
  const S = mod(4n * X * Y * Y), M = mod(3n * X * X), X3 = mod(M * M - 2n * S), Y3 = mod(M * (S - X3) - 8n * Y * Y * Y * Y), Z3 = mod(2n * Y * Z);
  return [X3, Y3, Z3];
}
function jAdd(p, q) {
  if (p[2] === 0n) return q; if (q[2] === 0n) return p;
  const [X1, Y1, Z1] = p, [X2, Y2, Z2] = q;
  const U1 = mod(X1 * Z2 * Z2), U2 = mod(X2 * Z1 * Z1), S1 = mod(Y1 * Z2 * Z2 * Z2), S2 = mod(Y2 * Z1 * Z1 * Z1);
  if (U1 === U2) return S1 === S2 ? jDouble(p) : [0n, 0n, 0n];
  const H = mod(U2 - U1), R = mod(S2 - S1), H2 = mod(H * H), H3 = mod(H * H2), U1H2 = mod(U1 * H2);
  const X3 = mod(R * R - H3 - 2n * U1H2), Y3 = mod(R * (U1H2 - X3) - S1 * H3), Z3 = mod(H * Z1 * Z2);
  return [X3, Y3, Z3];
}
function jMul(pt, k) { let r = [0n, 0n, 0n], a = [pt[0], pt[1], 1n]; while (k > 0n) { if (k & 1n) r = jAdd(r, a); a = jDouble(a); k >>= 1n; } return r; }
function toAffine([X, Y, Z]) { if (Z === 0n) return null; const zi = inv(Z), zi2 = mod(zi * zi); return [mod(X * zi2), mod(Y * zi2 * zi)]; }

function recoverAddress(hashHex, sigHex) {
  const sig = String(sigHex).replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{130}$/.test(sig)) throw new Error("bad signature format");
  const r = BigInt("0x" + sig.slice(0, 64)), s = BigInt("0x" + sig.slice(64, 128));
  let v = parseInt(sig.slice(128, 130), 16); if (v >= 27) v -= 27;
  if (v !== 0 && v !== 1) throw new Error("bad recovery id");
  if (r <= 0n || r >= N || s <= 0n || s >= N) throw new Error("bad signature values");
  const x = r, y2 = mod(x * x * x + 7n), yRoot = powm(y2, (P + 1n) / 4n, P);
  if (mod(yRoot * yRoot) !== y2) throw new Error("invalid point");
  const y = (yRoot & 1n) === BigInt(v) ? yRoot : P - yRoot;
  const z = BigInt(hashHex) % N, ri = inv(r, N);
  const sR = jMul([x, y], s), zG = jMul(G, mod(N - z, N));
  const Q = toAffine(jMul(toAffine(jAdd(sR, zG)) || [0n, 0n], ri));
  if (!Q) throw new Error("recovery failed");
  const pub = Buffer.from(Q[0].toString(16).padStart(64, "0") + Q[1].toString(16).padStart(64, "0"), "hex");
  return "0x" + keccak256(pub).slice(-40);
}
const personalHash = (msg) => keccak256(Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${Buffer.byteLength(msg)}`), Buffer.from(msg)]));

// ---------- holder pass ----------
const isAddr = (a) => /^0x[0-9a-fA-F]{40}$/.test(String(a || ""));
function createHolder({ env, site }) {
  const SECRET = env("HOLDER_SECRET", "") || crypto.randomBytes(32).toString("hex");
  const tiers = () => String(env("HOLDER_TIERS", "OBSERVER:100000,ANALYST:1000000,ORACLE:5000000")).split(",").map((s) => { const [name, min] = s.split(":"); return { name: name.trim().toUpperCase(), min: Number(min) }; }).filter((t) => t.name && t.min > 0).sort((a, b) => a.min - b.min);
  const PERKS = {
    OBSERVER: { agentPerMinute: 15, deepRescan: true, watchlist: 5 },
    ANALYST: { agentPerMinute: 30, deepRescan: true, watchlist: 20 },
    ORACLE: { agentPerMinute: 60, deepRescan: true, watchlist: 50 },
  };
  const perksFor = (tier) => PERKS[tier] || { agentPerMinute: Math.round((PERKS.OBSERVER.agentPerMinute + PERKS.ANALYST.agentPerMinute) / 2), deepRescan: true, watchlist: 10 };
  const nonces = new Map(), balCache = new Map();
  const token = () => String(site().TOKEN_CA || "").trim();
  const active = () => isAddr(token());

  function message(addr, nonce, issued) {
    const s = site();
    return `${s.PROJECT_NAME || "OBSERV"} Holder Pass\n\nSign in to unlock holder perks.\nThis signature is free. It never sends a transaction, never approves tokens and never moves funds.\n\nWallet: ${addr.toLowerCase()}\nChain: ${s.CHAIN_NAME || "Robinhood Chain"} (${s.CHAIN_ID || 4663})\nNonce: ${nonce}\nIssued: ${issued}`;
  }
  function challenge(addr) {
    if (!active()) return { error: "Holder Pass activates when the token contract is published." };
    if (!isAddr(addr)) return { error: "send a 0x wallet address" };
    const nonce = crypto.randomBytes(9).toString("base64url"), issued = new Date().toISOString();
    nonces.set(nonce, { addr: addr.toLowerCase(), issued, exp: Date.now() + 5 * 60e3 });
    if (nonces.size > 5000) nonces.delete(nonces.keys().next().value);
    return { nonce, message: message(addr, nonce, issued) };
  }
  async function balanceOf(addr) {
    const a = addr.toLowerCase(), c = balCache.get(a);
    if (c && Date.now() - c.at < 10 * 60e3) return c;
    const t = token(), data = "0x70a08231" + a.slice(2).padStart(64, "0");
    const [raw, dec] = await Promise.all([rpc("eth_call", [{ to: t, data }, "latest"]), rpc("eth_call", [{ to: t, data: "0x313ce567" }, "latest"]).catch(() => "0x12")]);
    const decimals = Number(BigInt(dec || "0x12")), units = BigInt(raw && raw !== "0x" ? raw : "0x0");
    const whole = Number(units / 10n ** BigInt(Math.min(decimals, 36)));
    const tier = tiers().filter((x) => whole >= x.min).pop();
    const out = { at: Date.now(), balance: whole, tier: tier ? tier.name : null };
    balCache.set(a, out); if (balCache.size > 20000) balCache.delete(balCache.keys().next().value);
    return out;
  }
  const sign = (body) => crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  function issue(addr, tier) {
    const body = Buffer.from(JSON.stringify({ a: addr.toLowerCase(), t: tier, exp: Date.now() + 24 * 3600e3 })).toString("base64url");
    return body + "." + sign(body);
  }
  function parse(pass) {
    const [body, mac] = String(pass || "").split(".");
    if (!body || !mac) return null;
    const good = sign(body);
    if (mac.length !== good.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(good))) return null;
    try { const j = JSON.parse(Buffer.from(body, "base64url").toString()); return j.exp > Date.now() && isAddr(j.a) ? j : null; } catch (_) { return null; }
  }
  async function verify({ address, nonce, signature }) {
    if (!active()) return { status: 409, body: { error: "Holder Pass activates when the token contract is published." } };
    const n = nonces.get(String(nonce || ""));
    if (!n || n.exp < Date.now() || n.addr !== String(address || "").toLowerCase()) return { status: 400, body: { error: "Sign-in expired. Try again." } };
    nonces.delete(nonce);
    let signer; try { signer = recoverAddress(personalHash(message(n.addr, nonce, n.issued)), signature); } catch (e) { return { status: 400, body: { error: "Invalid signature." } }; }
    if (signer.toLowerCase() !== n.addr) return { status: 401, body: { error: "Signature does not match this wallet." } };
    const b = await balanceOf(n.addr);
    if (!b.tier) return { status: 200, body: { holder: false, address: n.addr, balance: b.balance, tiers: tiers(), message: "No holder tier yet for this wallet." } };
    return { status: 200, body: { holder: true, pass: issue(n.addr, b.tier), address: n.addr, balance: b.balance, tier: b.tier, perks: perksFor(b.tier), tiers: tiers() } };
  }
  // pass → live tier (re-checks balance every 10 min, so selling drops the tier)
  async function resolve(req) {
    const j = parse(req.headers["x-observ-pass"]); if (!j || !active()) return null;
    try { const b = await balanceOf(j.a); return b.tier ? { address: j.a, tier: b.tier, balance: b.balance, perks: perksFor(b.tier) } : null; } catch (_) { return { address: j.a, tier: j.t, perks: perksFor(j.t) }; }
  }
  const info = () => ({ active: active(), tiers: tiers(), perks: PERKS });
  const tierOf = async (a) => (active() ? (await balanceOf(String(a))).tier : null);
  return { challenge, verify, resolve, info, tierOf, recoverAddress, personalHash };
}
module.exports = { createHolder, recoverAddress, personalHash };
