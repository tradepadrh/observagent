// OBSERV AGENT brain: Claude (Anthropic Messages API) with tools over the server's live data.
// The key stays on the server (ANTHROPIC_API_KEY in Railway). UI-only tools (focus_visual, open_view)
// are not executed here: they are returned as `actions` for the browser to perform.
const CFG = {
  key: (process.env.ANTHROPIC_API_KEY || "").trim().replace(/^["']|["']$/g, "").trim(),
  model: (process.env.ANTHROPIC_MODEL || "claude-sonnet-5-5").trim().replace(/^["']|["']$/g, ""),
  maxTokens: +process.env.AI_MAX_TOKENS || 600,
  perMinute: +process.env.AI_PER_IP_PER_MINUTE || 6,
  perDay: +process.env.AI_DAILY_LIMIT || 800,
  rounds: 5,
};

const UI_TOOLS = [
  { name: "focus_visual", description: "Move the 3D camera to spotlight the relevant region: core (chain nucleus), chain (block flow), bands (token-launch data rings), overview.",
    input_schema: { type: "object", properties: { target: { type: "string", enum: ["core", "chain", "bands", "overview"] } }, required: ["target"] } },
  { name: "open_view", description: "Open a view in the user's browser: certificate (genesis certificate + threat scan of a token, pass ca), daily (The 4663 Daily), roadmap, radar (threat radar), token (this project's CA + developer), coverage (chains & launchpads), kit (Agent Kit).",
    input_schema: { type: "object", properties: { view: { type: "string", enum: ["certificate", "daily", "roadmap", "radar", "token", "coverage", "kit"] }, ca: { type: "string" } }, required: ["view"] } },
];

function systemPrompt(ctx) {
  const o = ctx.official;
  return `You are "${o.name}", an autonomous AI agent observing live activity on Robinhood Chain (Ethereum L2, chain ID 4663): token launches across ${ctx.padNames.length} launchpads (${ctx.padNames.join(", ")}), new DEX pools, graduations, stock-token (equity) flows and heuristic threat signals.
Explain what is happening on-chain in crisp, confident, slightly futuristic English, like a mission-control briefing. Always reply in English, even if the user writes in another language.
Rules:
- For any number, ALWAYS pull it from tools. Never invent figures, contract addresses or handles.
- Factual observation only. Never give buy/sell/hold advice, never predict prices, never call a token "safe" or a "scam". If asked, decline in one short sentence and offer factual data instead.
- For danger/risk/rug/scam questions call scan_token_risk and report score, level and each signal with its evidence as "signals detected". Always add that a low score does not mean safe.
- For this project's own token, call get_project_info and quote it exactly. If contract_address is null, say the token has not launched yet and any CA circulating is unofficial.
- Name the launchpad a token came from when relevant. Live coverage is Robinhood Chain only; other chains are on the roadmap (get_coverage).
- Call focus_visual to spotlight the visual region most relevant to your answer. Call open_view only when the user asks to see something.
- Max 110 words, plain text, no headings or lists. You may use **bold** for key figures.`;
}

// Human-readable reason for an Anthropic error (never echoes the key).
function explain(status, raw) {
  let type = "", msg = "";
  try { const e = JSON.parse(raw).error || {}; type = e.type || ""; msg = String(e.message || ""); } catch (_) {}
  if (status === 401 || type === "authentication_error") return "AI upstream error 401 — ANTHROPIC_API_KEY was rejected. Re-copy the key (sk-ant-…) into Railway Variables, no quotes or spaces, then redeploy.";
  if (status === 403 || type === "permission_error") return "AI upstream error 403 — this API key has no permission for the model. Check the key's workspace in console.anthropic.com.";
  if (/credit balance/i.test(msg)) return "AI upstream error — the Anthropic account has no credit. Add credit at console.anthropic.com → Billing.";
  if (status === 404 || type === "not_found_error") return `AI upstream error 404 — model "${CFG.model}" not found for this key. Set ANTHROPIC_MODEL to a model your key can use.`;
  if (status === 429) return "AI uplink saturated — retry in a moment.";
  if (status === 529 || type === "overloaded_error") return "AI upstream overloaded — retry in a moment.";
  return `AI upstream error ${status}${msg ? " — " + msg.slice(0, 160) : ""}`;
}

function createAI(tools) {
  // tools: [{name, description, input_schema, run(input) -> data}]
  const byIp = new Map();
  let day = new Date().toDateString(), today = 0;
  const enabled = () => !!CFG.key;

  function limited(ip) {
    const now = Date.now(), d = new Date().toDateString();
    if (d !== day) { day = d; today = 0; }
    if (today >= CFG.perDay) return "daily";
    const arr = (byIp.get(ip) || []).filter((t) => now - t < 60000);
    if (arr.length >= CFG.perMinute) return "minute";
    arr.push(now); byIp.set(ip, arr); today++;
    if (byIp.size > 5000) byIp.delete(byIp.keys().next().value);
    return null;
  }

  async function ask({ q, history = [], ip = "?" }, ctx) {
    if (!enabled()) return { status: 503, body: { error: "AI is not configured (ANTHROPIC_API_KEY missing)", fallback: true } };
    const lim = limited(ip);
    if (lim) return { status: 429, body: { error: lim === "daily" ? "Daily AI budget reached. Try again tomorrow." : "Too many questions — wait a minute.", fallback: true } };
    const question = String(q || "").slice(0, 600).trim();
    if (!question) return { status: 400, body: { error: "empty question" } };

    const messages = [];
    for (const h of history.slice(-3)) if (h && h.q && h.a) { messages.push({ role: "user", content: String(h.q).slice(0, 600) }); messages.push({ role: "assistant", content: String(h.a).slice(0, 1200) }); }
    messages.push({ role: "user", content: question });
    const toolDefs = [...tools.map(({ name, description, input_schema }) => ({ name, description, input_schema })), ...UI_TOOLS];
    const used = [], actions = [];

    for (let round = 0; round < CFG.rounds; round++) {
      const res = await fetch((process.env.ANTHROPIC_BASE || "https://api.anthropic.com") + "/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": CFG.key, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: CFG.model, max_tokens: CFG.maxTokens, system: systemPrompt(ctx), tools: toolDefs, messages }),
        signal: AbortSignal.timeout(45000),
      });
      if (!res.ok) {
        const t = await res.text().catch(() => "");
        console.warn("anthropic", res.status, t.slice(0, 300));
        return { status: res.status === 429 ? 429 : 502, body: { error: explain(res.status, t), fallback: true } };
      }
      const j = await res.json();
      messages.push({ role: "assistant", content: j.content });
      const calls = (j.content || []).filter((b) => b.type === "tool_use");
      if (j.stop_reason !== "tool_use" || !calls.length) {
        const text = (j.content || []).filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
        return { status: 200, body: { text, tools: used, actions, model: CFG.model } };
      }
      const results = [];
      for (const c of calls) {
        used.push(c.name);
        if (c.name === "focus_visual" || c.name === "open_view") { actions.push({ tool: c.name, input: c.input || {} }); results.push({ type: "tool_result", tool_use_id: c.id, content: JSON.stringify({ ok: true }) }); continue; }
        const t = tools.find((x) => x.name === c.name);
        try {
          const out = t ? await t.run(c.input || {}) : { error: "unknown tool" };
          results.push({ type: "tool_result", tool_use_id: c.id, content: JSON.stringify(out).slice(0, 12000) });
        } catch (e) { results.push({ type: "tool_result", tool_use_id: c.id, is_error: true, content: String(e.message || e) }); }
      }
      messages.push({ role: "user", content: results });
    }
    return { status: 200, body: { text: "Signal too complex to resolve in one pass — try a narrower question.", tools: used, actions } };
  }
  return { ask, enabled, model: () => CFG.model };
}

module.exports = { createAI };
