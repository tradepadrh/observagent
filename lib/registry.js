// Coverage registry: which chains OBSERV AGENT watches and how each launchpad works.
// Launchpad contracts live in launchpads.js (scanner). Add more without code via LAUNCHPADS_JSON,
// and override this display info via CHAINS_JSON / PAD_INFO_JSON in Railway.
const CHAINS = [
  { id: "robinhood", name: "Robinhood Chain", chainId: 4663, status: "live", note: "Arbitrum Orbit L2 · tokenized equities" },
  { id: "elysium", name: "Elysium", chainId: null, status: "planned", priority: true, note: "Hyperliquid L2 by Kinetiq · Arbitrum Orbit · settles to HyperEVM" },
  { id: "base", name: "Base", chainId: 8453, status: "planned", note: "Coinbase L2 · agent & memecoin hub" },
  { id: "arbitrum", name: "Arbitrum One", chainId: 42161, status: "planned", note: "Same stack as Robinhood Chain" },
  { id: "bnb", name: "BNB Chain", chainId: 56, status: "planned", note: "High-volume launchpad market" },
  { id: "ethereum", name: "Ethereum", chainId: 1, status: "research", note: "L1 settlement layer" },
  { id: "solana", name: "Solana", chainId: null, status: "research", note: "Non-EVM · separate indexer stack" },
];

// display info per scanner key (launchpads.js). code = short tag shown on the stage.
const PAD_INFO = {
  pons: { code: "PONS", model: "Pons V2 bonding curve → DEX graduation", curve: true },
  flap: { code: "FLAP", model: "Bonding curve · vanity 8888/7777 addresses", curve: true },
  poolstrade: { code: "POOLS", model: "Uniswap Labs launchpad · locked v4 pools", locked: true },
  clanker: { code: "CLNK", model: "Direct Uniswap v4 deploy" },
  virtuals: { code: "VIRT", model: "AI-agent token launches" },
  hoodfun: { code: "HOOD", model: "Bonding-curve launchpad", curve: true },
  launchhood: { code: "LHOOD", model: "Launchpad contract" },
  klik: { code: "KLIK", model: "Launchpad contract" },
  doppler: { code: "DOPL", model: "Doppler auctions → Uniswap v4" },
  apestore: { code: "APE", model: "Bonding-curve launchpad", curve: true },
  bags: { code: "BAGS", model: "Launchpad contract" },
  trench: { code: "TRNCH", model: "Launchpad contract" },
  dex: { code: "DEX", model: "Pool created directly on a DEX (no known launchpad)" },
  // not scanned until their contracts are added with LAUNCHPADS_JSON
  fobo: { code: "FOBO", model: "Uniswap v4 hook · rising price floor", standby: true },
  ascend: { code: "ASCND", model: "Kinetiq launchpad on Elysium", chain: "elysium", standby: true },
};

function load() {
  let chains = CHAINS, info = { ...PAD_INFO };
  try { if (process.env.CHAINS_JSON) chains = JSON.parse(process.env.CHAINS_JSON); } catch (e) { console.warn("CHAINS_JSON ignored:", e.message); }
  try { Object.assign(info, JSON.parse(process.env.PAD_INFO_JSON || "{}")); } catch (e) { console.warn("PAD_INFO_JSON ignored:", e.message); }
  return { chains, info };
}

// registry shape the web UI expects: chains + launchpads [{id,name,code,chain,model,...,standby}]
function forWeb(scannerPads) {
  const { chains, info } = load();
  const seen = new Set();
  const pads = scannerPads.map((p) => {
    seen.add(p.key);
    const i = info[p.key] || {};
    return { id: p.key, name: i.name || p.name.charAt(0) + p.name.slice(1).toLowerCase(), code: i.code || p.name.slice(0, 5), chain: i.chain || "robinhood", model: i.model || "Launchpad contract", curve: !!i.curve, locked: !!i.locked, standby: !(p.addrs && p.addrs.length) };
  });
  pads.push({ id: "dex", name: "Direct DEX", code: "DEX", chain: "robinhood", model: info.dex.model });
  for (const [key, i] of Object.entries(info)) if (!seen.has(key) && key !== "dex") pads.push({ id: key, name: i.name || key.toUpperCase(), code: i.code || key.toUpperCase(), chain: i.chain || "robinhood", model: i.model || "", standby: true });
  return { chains, launchpads: pads };
}

module.exports = { forWeb, load };
