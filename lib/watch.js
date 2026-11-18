// WATCHLIST ALERTS — server-side monitoring for Holder Pass wallets.
// Each holder watches up to N addresses (tier cap). Every tick the server reads new Transfer logs for:
//   - watched TOKENS  (address filter)        → whale moves, creator moves
//   - watched WALLETS (topic filter, from/to) → buys, sells, transfers of any token
// plus live events (launch by a watched wallet, threat flags / score jumps on a watched token).
// Alerts land in the web app (polled) and, if linked, in Telegram. Read-only: nothing here signs or sends funds.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const lc = (s) => String(s || "").toLowerCase();
const isAddr = (a) => /^0x[0-9a-f]{40}$/.test(lc(a));
const short = (a) => (a ? a.slice(0, 6) + "…" + a.slice(-4) : "?");
const pad32 = (a) => "0x" + lc(a).slice(2).padStart(64, "0");
const addrOf = (w) => "0x" + String(w).replace(/^0x/, "").slice(-40).toLowerCase();
const toHex = (n) => "0x" + n.toString(16);
const fmtAmt = (x) => (x >= 1e9 ? (x / 1e9).toFixed(2) + "B" : x >= 1e6 ? (x / 1e6).toFixed(2) + "M" : x >= 1e3 ? (x / 1e3).toFixed(1) + "K" : x >= 1 ? x.toFixed(2) : x.toPrecision(3));
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);

function createWatch({ env, rpc, keccak256, launchpads, threat, holder, site }) {
  const CFG = {
    file: env("WATCH_FILE", path.join(__dirname, "..", "data", "watch.json")),
    intervalMs: Math.max(10, +env("WATCH_INTERVAL_SECONDS", 20)) * 1000,
    whalePct: +env("WATCH_WHALE_PCT", 0.5) / 100, // share of supply that counts as a whale move
    creatorPct: 0.0005,
    maxRange: 3000,
    keepAlerts: 60,
    perTickPerUser: 12,
    tgToken: env("TELEGRAM_BOT_TOKEN"),
  };
  const T_TRANSFER = keccak256("Transfer(address,address,uint256)");
  const users = new Map(); // holder address -> { items:[addr], tier, tg:{chat}|null, alerts:[], seen:{} }
  let cursor = 0, timer = null, saving = null, lastError = null;

  // ---------- persistence (survives restarts when the data folder is on a volume) ----------
  try {
    const raw = JSON.parse(fs.readFileSync(CFG.file, "utf8"));
    for (const [a, u] of Object.entries(raw.users || {})) users.set(a, { items: (u.items || []).filter(isAddr), tier: u.tier || null, tg: u.tg || null, alerts: u.alerts || [] });
  } catch (_) {}
  function save() {
    clearTimeout(saving);
    saving = setTimeout(() => {
      try { fs.mkdirSync(path.dirname(CFG.file), { recursive: true }); fs.writeFileSync(CFG.file, JSON.stringify({ users: Object.fromEntries(users) })); } catch (e) { console.warn("watch save", e.message); }
    }, 1500);
  }
  const user = (a) => { a = lc(a); if (!users.has(a)) users.set(a, { items: [], tier: null, tg: null, alerts: [] }); return users.get(a); };

  // ---------- token facts (cached) ----------
  const metaCache = new Map(), codeCache = new Map();
  async function meta(token) {
    if (metaCache.has(token)) return metaCache.get(token);
    let m = { symbol: short(token), decimals: 18, supply: 0n };
    try { const x = await launchpads.erc20Meta(token); m.symbol = x.symbol || m.symbol; m.decimals = x.decimals == null ? 18 : x.decimals; } catch (_) {}
    try { const r = await rpc("eth_call", [{ to: token, data: "0x18160ddd" }, "latest"]); m.supply = r && r !== "0x" ? BigInt(r) : 0n; } catch (_) {}
    metaCache.set(token, m); return m;
  }
  async function isContract(a) {
    if (codeCache.has(a)) return codeCache.get(a);
    let c = false; try { const code = await rpc("eth_getCode", [a, "latest"]); c = !!code && code !== "0x" && !/^0xef0100[0-9a-f]{40}$/i.test(code); } catch (_) {}
    codeCache.set(a, c); if (codeCache.size > 5000) codeCache.clear(); return c;
  }
  async function creatorOf(token) {
    try { const d = await launchpads.deployerOf(token); if (d) return lc(d); } catch (_) {}
    const s = threat.cached && threat.cached(token); return s && s.metrics && s.metrics.deployer ? lc(s.metrics.deployer) : null;
  }

  // ---------- alert delivery ----------
  const SITE_URL = () => (site().SITE_URL || site().WEBSITE_URL || "").replace(/\/$/, "");
  const EXP = () => (site().EXPLORER_URL || "https://robinhoodchain.blockscout.com").replace(/\/$/, "");
  function alert(addr, a) {
    const u = users.get(addr); if (!u) return;
    const key = a.key || a.tx + a.text; u.seenKeys = u.seenKeys || new Set();
    if (u.seenKeys.has(key)) return; u.seenKeys.add(key); if (u.seenKeys.size > 400) u.seenKeys = new Set([...u.seenKeys].slice(-200));
    const rec = { id: crypto.randomBytes(5).toString("hex"), t: new Date().toISOString(), kind: a.kind, text: a.text, token: a.token || null, watched: a.watched, tx: a.tx || null };
    u.alerts.unshift(rec); if (u.alerts.length > CFG.keepAlerts) u.alerts.length = CFG.keepAlerts;
    save();
    if (u.tg && u.tg.chat) tgSend(u.tg.chat, tgText(rec)).catch(() => {});
  }
  function tgText(r) {
    const links = [];
    if (r.token && SITE_URL()) links.push(`<a href="${SITE_URL()}/#scan=${r.token}">X-Ray</a>`);
    if (r.tx) links.push(`<a href="${EXP()}/tx/${r.tx}">tx</a>`);
    return `<b>OBSERV · WATCHLIST</b>\n${esc(r.text)}${links.length ? "\n" + links.join(" · ") : ""}`;
  }
  // which users watch this address?
  function watchers(a) { const out = []; for (const [h, u] of users) if (u.tier && u.items.includes(a)) out.push(h); return out; }

  // ---------- chain tick ----------
  async function logs(filter, from, to) {
    try { return await rpc("eth_getLogs", [{ ...filter, fromBlock: toHex(from), toBlock: toHex(to) }]); }
    catch (e) {
      if (to - from > 200 && /range|limit|too many|exceed|10000|results/i.test(String(e.message))) { const mid = from + Math.floor((to - from) / 2); return [...(await logs(filter, from, mid)), ...(await logs(filter, mid + 1, to))]; }
      throw e;
    }
  }
  async function tick() {
    const all = new Set(); for (const u of users.values()) if (u.tier) for (const a of u.items) all.add(a);
    if (!all.size) return;
    const latest = parseInt(await rpc("eth_blockNumber", []), 16);
    if (!cursor) cursor = latest - 50;
    if (latest <= cursor) return;
    const from = Math.max(cursor + 1, latest - CFG.maxRange), to = latest;
    const list = [...all], topics = list.map(pad32);
    const [tok, out, inn] = await Promise.all([
      logs({ address: list, topics: [T_TRANSFER] }, from, to),
      logs({ topics: [T_TRANSFER, topics] }, from, to),
      logs({ topics: [T_TRANSFER, null, topics] }, from, to),
    ]);
    cursor = to;
    const budget = new Map();
    const send = (h, a) => { const n = budget.get(h) || 0; if (n >= CFG.perTickPerUser) return; budget.set(h, n + 1); alert(h, a); };
    const seenTx = new Set();
    for (const lg of [...tok, ...out, ...inn]) {
      if (!lg.topics || lg.topics.length !== 3) continue; // ERC-721 has 4 topics
      const id = lg.transactionHash + ":" + lg.logIndex; if (seenTx.has(id)) continue; seenTx.add(id);
      const token = lc(lg.address), f = addrOf(lg.topics[1]), t = addrOf(lg.topics[2]);
      const raw = BigInt(lg.data && lg.data !== "0x" ? lg.data : "0x0"); if (raw === 0n) continue;
      const m = await meta(token), amt = Number(raw) / 10 ** m.decimals, pct = m.supply > 0n ? Number((raw * 1000000n) / m.supply) / 1e6 : 0;
      const sym = "$" + String(m.symbol).replace(/^\$/, "");
      // watched token: whale or creator moves
      if (all.has(token)) {
        const creator = await creatorOf(token);
        const byCreator = creator && (f === creator || t === creator);
        if (pct >= CFG.whalePct || (byCreator && pct >= CFG.creatorPct)) {
          const [fc, tc] = await Promise.all([isContract(f), isContract(t)]);
          const dir = fc && !tc ? "BUY" : tc && !fc ? "SELL" : "MOVE";
          const who = byCreator ? (f === creator ? "Creator" : "To creator") : "Whale";
          const icon = dir === "SELL" ? "🔻" : dir === "BUY" ? "🟢" : "🔁";
          const text = `${icon} ${sym} · ${who} ${dir} ${fmtAmt(amt)} (${(pct * 100).toFixed(2)}% of supply) · ${short(f)} → ${short(t)}`;
          for (const h of watchers(token)) send(h, { kind: byCreator ? "creator" : "whale", text, token, watched: token, tx: lg.transactionHash, key: id });
        }
      }
      // watched wallets: anything they send or receive
      for (const w of [f, t]) {
        if (!all.has(w) || w === token) continue;
        const peer = w === f ? t : f, [pc] = await Promise.all([isContract(peer)]);
        const dir = w === t ? (pc ? "BOUGHT" : "RECEIVED") : pc ? "SOLD" : "SENT";
        const icon = dir === "SOLD" ? "🔻" : dir === "BOUGHT" ? "🟢" : "↔";
        const text = `${icon} Wallet ${short(w)} ${dir} ${fmtAmt(amt)} ${sym}${pct >= 0.001 ? ` (${(pct * 100).toFixed(2)}%)` : ""}`;
        for (const h of watchers(w)) send(h, { kind: "wallet", text, token, watched: w, tx: lg.transactionHash, key: id + w });
      }
    }
  }
  async function loop() {
    try { await tick(); lastError = null; } catch (e) { lastError = String(e.message || e).slice(0, 160); }
    timer = setTimeout(loop, CFG.intervalMs);
  }

  // ---------- live events from the observatory ----------
  function onEvent(ev) {
    if (!ev) return;
    if (ev.type === "launch") {
      const d = lc(ev.deployer);
      if (d) for (const h of watchers(d)) alert(h, { kind: "launch", text: `🚀 Watched wallet ${short(d)} launched $${ev.sym || "?"} on ${ev.padName || "a launchpad"}`, token: lc(ev.token), watched: d, tx: ev.tx, key: "launch" + ev.token });
    }
  }
  const lastScore = new Map();
  function onScan(s) {
    if (!s || !s.token) return;
    const a = lc(s.token), prev = lastScore.get(a); lastScore.set(a, s.score);
    const ws = watchers(a); if (!ws.length) return;
    if (prev == null ? s.score >= 50 : s.score >= prev + 15) {
      const text = `⚠ $${s.symbol || "?"} threat score ${prev == null ? "" : prev + " → "}${s.score}/100 (${s.level})${s.top ? " · " + s.top : ""}`;
      for (const h of ws) alert(h, { kind: "threat", text, token: a, watched: a, key: "threat" + a + s.score });
    }
  }

  // ---------- Telegram (optional) ----------
  let bot = null, tgOffset = 0; const codes = new Map(); // code -> { addr, exp }
  async function tg(method, body) {
    const r = await fetch(`https://api.telegram.org/bot${CFG.tgToken}/${method}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}), signal: AbortSignal.timeout(35000) });
    const j = await r.json(); if (!j.ok) throw new Error(j.description || "telegram error"); return j.result;
  }
  const tgSend = (chat, text) => tg("sendMessage", { chat_id: chat, text, parse_mode: "HTML", disable_web_page_preview: true });
  async function tgLoop() {
    try {
      const ups = await tg("getUpdates", { offset: tgOffset, timeout: 25, allowed_updates: ["message"] });
      for (const up of ups) {
        tgOffset = up.update_id + 1;
        const m = up.message; if (!m || !m.text) continue;
        const chat = m.chat.id, txt = m.text.trim();
        const start = txt.match(/^\/start(?:\s+(\w+))?/);
        if (start && start[1] && codes.has(start[1]) && codes.get(start[1]).exp > Date.now()) {
          const { addr } = codes.get(start[1]); codes.delete(start[1]);
          for (const u of users.values()) if (u.tg && u.tg.chat === chat) u.tg = null; // one wallet per chat
          user(addr).tg = { chat }; save();
          await tgSend(chat, `<b>OBSERV · WATCHLIST</b>\n✅ Linked to ${short(addr)}. Alerts for your watchlist will arrive here.\nSend /stop to unlink.`);
        } else if (/^\/stop/.test(txt)) {
          for (const u of users.values()) if (u.tg && u.tg.chat === chat) u.tg = null; save();
          await tgSend(chat, "Unlinked. No more watchlist alerts here.");
        } else if (start) {
          await tgSend(chat, "Open observagent.tech → Holder Pass → Watchlist → CONNECT TELEGRAM to link your wallet.");
        }
      }
    } catch (e) { if (!/timeout|aborted/i.test(String(e.message))) { lastError = "telegram: " + String(e.message).slice(0, 120); await new Promise((r) => setTimeout(r, 5000)); } }
    setImmediate(tgLoop);
  }

  // ---------- API (holder-gated by the caller) ----------
  function view(addr, h) {
    const u = user(addr);
    return { items: u.items, cap: h.perks.watchlist, tier: h.tier, alerts: u.alerts.slice(0, 30), telegram: { enabled: !!bot, bot: bot ? bot.username : null, linked: !!(u.tg && u.tg.chat) }, interval_seconds: CFG.intervalMs / 1000 };
  }
  function setItems(addr, h, items) {
    const clean = [...new Set((items || []).map(lc).filter(isAddr))];
    if (clean.length > h.perks.watchlist) return { error: `Your tier watches up to ${h.perks.watchlist} addresses.` };
    const u = user(addr); u.items = clean; u.tier = h.tier; save();
    return view(addr, h);
  }
  function telegramLink(addr) {
    if (!bot) return { error: "Telegram alerts are not enabled on this server." };
    const code = crypto.randomBytes(6).toString("hex"); codes.set(code, { addr: lc(addr), exp: Date.now() + 15 * 60000 });
    return { link: `https://t.me/${bot.username}?start=${code}`, expires_minutes: 15 };
  }
  function telegramUnlink(addr) { const u = user(addr); u.tg = null; save(); return { ok: true }; }
  // holders whose balance fell below every tier stop receiving alerts (re-checked every 10 minutes)
  async function recheck() {
    for (const [a, u] of users) { if (!u.items.length) continue; try { const t = await holder.tierOf(a); if (t !== undefined) u.tier = t; } catch (_) {} }
    save();
  }

  function start() {
    loop();
    setInterval(() => recheck().catch(() => {}), 10 * 60000);
    if (CFG.tgToken) tg("getMe").then((me) => { bot = me; tg("deleteWebhook", {}).catch(() => {}); tgLoop(); console.log("watch: telegram bot @" + me.username); }).catch((e) => { lastError = "telegram: " + e.message; console.warn("watch telegram", e.message); });
  }
  const status = () => ({ users: [...users.values()].filter((u) => u.items.length).length, watched: new Set([...users.values()].flatMap((u) => (u.tier ? u.items : []))).size, cursor, telegram: bot ? "@" + bot.username : null, lastError });
  return { start, onEvent, onScan, view, setItems, telegramLink, telegramUnlink, status, _tick: tick };
}
module.exports = { createWatch };
