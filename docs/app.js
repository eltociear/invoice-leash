// Desk Console (docs/app.html). Static: reads and writes the QoreChain testnet from the browser, no server.
// Data from docs/app-data.json (scripts/app.mjs). The wallet is any EIP-1193 provider (window.ethereum).
(async () => {
  const E = window.ethers;
  const $ = (id) => document.getElementById(id);
  const h = (x) => String(x ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const D = await (await fetch("app-data.json")).json();
  const ZERO = "0x0000000000000000000000000000000000000000", CHAIN_HEX = "0x" + D.chain.chainId.toString(16);
  const i2 = new E.Interface(D.abiV2), i3 = new E.Interface(D.abiV3), i4 = new E.Interface(D.abiV4);
  const erc = new E.Interface(["function balanceOf(address) view returns (uint256)", "function allowance(address,address) view returns (uint256)"]);
  const pqc = new E.Interface(["function pqcKeyStatus(address) view returns (bool registered,uint8 algorithmId,bytes pubkey,bool possessionProven)"]);
  const DOMAIN = E.keccak256(E.toUtf8Bytes("LEASH-INVOICE-v2"));
  const fusd = (v) => E.formatUnits(v, 6).replace(/\.0$/, "") + " fUSD";
  const qor = (v) => E.formatEther(v).replace(/(\.\d{4})\d+$/, "$1") + " QOR";
  const txl = (hash) => `<a href="${D.chain.explorer}${h(hash)}" target="_blank" rel="noopener">${h(hash.slice(0, 10))}…</a>`;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---- the chain, read directly (the testnet's EVM RPC allows browsers)
  async function rpc(method, params) {
    for (let i = 0; ; i++) {
      try {
        const r = await fetch(D.chain.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
        if (!r.ok) throw new Error(`the testnet RPC answered HTTP ${r.status}`);
        return await r.json();
      } catch (e) { if (i >= 3) throw e; await sleep(1200 * (i + 1)); }
    }
  }
  async function call(to, iface, fn, args) {
    const r = await rpc("eth_call", [{ to, data: iface.encodeFunctionData(fn, args) }, "latest"]);
    if (r.error) throw new Error(r.error.message);
    return iface.decodeFunctionResult(fn, r.result);
  }
  /** Ask a desk, without paying: "WOULD PAY", the desk's error name, or the chain's message. */
  async function ask(from, to, data, value) {
    const r = await rpc("eth_call", [{ from, to, data, ...(value ? { value: E.toQuantity(value) } : {}) }, "latest"]);
    if (!r.error) return "WOULD PAY";
    try { const n = i4.parseError(r.error.data)?.name; if (n) return n; } catch { /* not a desk error */ }
    return r.error.message;
  }
  async function logs(address, topics, from, to) {
    // 10,000-block windows (the RPC's limit), four at a time
    const starts = []; for (let b = from; b <= to; b += 10000) starts.push(b);
    const parts = new Array(starts.length); let next = 0;
    await Promise.all(Array.from({ length: 4 }, async () => {
      for (let i; (i = next++) < starts.length;) {
        const r = await rpc("eth_getLogs", [{ address, topics, fromBlock: E.toQuantity(starts[i]), toBlock: E.toQuantity(Math.min(starts[i] + 9999, to)) }]);
        if (r.error) throw new Error(r.error.message);
        parts[i] = r.result;
      }
    }));
    return parts.flat();
  }
  // qor1… for an 0x address (bech32), so the faucet can be pointed at a wallet's account
  const CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const polymod = (v) => { let c = 1; const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; for (const x of v) { const b = c >>> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((b >>> i) & 1) c ^= G[i]; } return c; };
  function toQor(addr) {
    const bytes = E.getBytes(addr), d = []; let acc = 0, bits = 0;
    for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; d.push((acc >>> bits) & 31); } acc &= (1 << bits) - 1; }
    if (bits) d.push((acc << (5 - bits)) & 31);
    const hrp = "qor", hx = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
    const p = polymod(hx.concat(d, [0, 0, 0, 0, 0, 0])) ^ 1;
    return hrp + "1" + d.concat([0, 1, 2, 3, 4, 5].map((i) => (p >>> (5 * (5 - i))) & 31)).map((x) => CH[x]).join("");
  }
  window.leashToQor = toQor; // for tests

  rpc("eth_blockNumber", []).then((r) => { $("live").textContent = `live: qorechain-diana, block ${parseInt(r.result, 16).toLocaleString()}`; }).catch(() => { $("live").textContent = "could not reach the testnet RPC"; });

  // ---- 1. watch a desk
  D.desks.forEach((d, k) => {
    const b = document.createElement("button"); b.textContent = d.name; b.setAttribute("aria-pressed", "false");
    b.onclick = () => { [...$("desks").children].forEach((x) => x.setAttribute("aria-pressed", "false")); b.setAttribute("aria-pressed", "true"); watch(k).catch((e) => { $("watch").innerHTML = `<span class="no">Could not read the chain: ${h(e.message)}</span>`; }); };
    $("desks").appendChild(b);
  });
  let watching = null; // the desk last picked: a slower answer for an earlier pick is dropped
  async function watch(k) {
    watching = k;
    const d = D.desks[k], iface = d.version === 4 ? i4 : d.version === 3 ? i3 : i2;
    $("watch").innerHTML = `<span class="dim">reading ${h(d.desk)} from the chain…</span>`;
    let from = d.deployBlock;
    if (!from && d.deployTx) from = parseInt((await rpc("eth_getTransactionReceipt", [d.deployTx])).result.blockNumber, 16);
    const head = parseInt((await rpc("eth_blockNumber", [])).result, 16);
    const [[on], lim, [left], [bal], [allow]] = await Promise.all([
      call(d.desk, iface, "isAgent", [d.payer, d.agent]), call(d.desk, iface, "limits", [d.payer, D.fusd]), call(d.desk, iface, "remainingToday", [d.payer, D.fusd]),
      call(D.fusd, erc, "balanceOf", [d.payer]), call(D.fusd, erc, "allowance", [d.payer, d.desk])]);
    // the desk's state first; its event history (slower: log scans and block times) fills in below
    if (watching !== k) return;
    $("watch").innerHTML =
      `<p class="dim small" style="margin-top:0">${h(d.note)} Desk <a class="mono" href="https://explore.qore.network/address/${h(d.desk)}">${h(d.desk)}</a> (InvoiceDeskV${d.version}).</p>
      <div class="grid">
        <div class="stat"><b class="${on ? "ok" : "no"}">${on ? "ON" : "OFF"}</b><span>the agent, in this desk</span></div>
        <div class="stat"><b>${fusd(lim[0])} / ${fusd(lim[1])}</b><span>agent limit: per payment / per UTC day</span></div>
        <div class="stat"><b>${fusd(left)}</b><span>the agent may still pay today</span></div>
        <div class="stat"><b>${fusd(bal)}</b><span>company's fUSD float (ERC-20)</span></div>
        <div class="stat"><b>${fusd(allow)}</b><span>what the desk may still pull</span></div>
      </div>
      <div id="wtables"><p class="dim small">reading the desk's vendors and payments from its events…</p></div>`;
    const payerTopic = E.zeroPadValue(d.payer, 32);
    const [va, paidLogs] = await Promise.all([logs(d.desk, [iface.getEvent("VendorApproved").topicHash, payerTopic], from, head), logs(d.desk, [iface.getEvent("InvoicePaid").topicHash, payerTopic], from, head)]);
    const vendors = new Map();
    for (const l of va) { const e = iface.parseLog(l); vendors.set(E.getAddress(e.args.vendor), e.args.approved); }
    const name = (a) => d.vendors[E.getAddress(a)] ?? d.vendors[a] ?? (E.getAddress(a) === E.getAddress(D.publicVendor.evm) ? "public test vendor" : "");
    const rows = await Promise.all(paidLogs.map(async (l) => {
      const e = iface.parseLog(l), blk = (await rpc("eth_getBlockByNumber", [l.blockNumber, false])).result;
      return { at: new Date(parseInt(blk.timestamp, 16) * 1000).toISOString(), what: `${name(e.args.vendor) || h(e.args.vendor.slice(0, 10))}: ${e.args.token === ZERO ? qor(e.args.amount) : fusd(e.args.amount)}`, by: E.getAddress(e.args.by) === E.getAddress(d.payer) ? "the company, in person" : "agent", tx: l.transactionHash };
    }));
    for (const p of d.agentPayments ?? []) rows.push({ at: p.at, what: h(p.label), by: "the agent (relayed)", tx: p.link.slice(-64) });
    rows.sort((a, b) => b.at.localeCompare(a.at));
    if (watching !== k) return;
    $("wtables").innerHTML =
      `<h3 style="margin-top:18px">Approved vendors (from the desk's own events)</h3>
      <table><tr><th>Vendor</th><th>Address</th><th>Approved</th></tr>${[...vendors].map(([a, ok]) => `<tr><td>${h(name(a))}</td><td class="mono small">${h(a)}</td><td class="${ok ? "ok" : "no"}">${ok ? "yes" : "removed"}</td></tr>`).join("") || `<tr><td colspan="3" class="dim">none</td></tr>`}</table>
      <h3 style="margin-top:18px">Payments (newest first)</h3>
      <table><tr><th>Paid (UTC)</th><th>Invoice</th><th>By</th><th>Tx</th></tr>${rows.slice(0, 20).map((r) => `<tr><td class="small">${h(r.at.slice(0, 16).replace("T", " "))}</td><td>${r.what}</td><td>${h(r.by)}</td><td>${txl(r.tx)}</td></tr>`).join("") || `<tr><td colspan="4" class="dim">none yet</td></tr>`}</table>
      <p class="dim small">The company's own payments come from the desk's <code>InvoicePaid</code> events. The agent's are relayed through a QoreChain authenticator (<code>MsgExecuteEVM</code>), which leaves no log <code>eth_getLogs</code> returns, so they are listed from the run's record, each a link to its transaction.</p>`;
  }
  $("desks").children[0].click();

  // ---- 2. your own desk, through your local signer (node desk.mjs serve): your keys stay on your machine
  const L = { url: null, token: null, snap: null };
  const hp = new URLSearchParams(location.hash.slice(1));
  if (hp.get("local")) $("lurl").value = hp.get("local");
  if (hp.get("token")) $("ltok").value = hp.get("token");
  const log = (title, r) => { $("llog").innerHTML = `<b>${h(title)}</b>: ${r.ok ? '<span class="ok">done</span>' : `<span class="no">${h(r.error ?? "failed")}</span>`}\n${h(r.log ?? "")}\n\n` + ($("llog").textContent === "Nothing yet." ? "" : $("llog").innerHTML); };
  async function local(method, path, body) {
    let r;
    try { r = await fetch(L.url + path, { method, headers: { authorization: `Bearer ${L.token}`, ...(body ? { "content-type": "application/json" } : {}) }, body }); }
    catch (e) { return { ok: false, error: `cannot reach ${L.url}: is node desk.mjs serve running? (${e.message})` }; }
    return r.json();
  }
  async function act(title, method, path, body) {
    const btns = [...document.querySelectorAll("#mine button")]; btns.forEach((b) => (b.disabled = true));
    $("llog").innerHTML = `<span class="dim">${h(title)}: working (each step is a real testnet transaction)…</span>\n` + $("llog").innerHTML;
    try { const r = await local(method, path, body); log(title, r); await refresh(); return r; } finally { btns.forEach((b) => (b.disabled = false)); }
  }
  async function refresh() {
    const r = await local("GET", "/status");
    if (!r.ok) { $("lstat").innerHTML = `<span class="no">${h(r.error)}</span>`; return; }
    const s = (L.snap = r.value);
    $("lstat").innerHTML = `<div class="grid" style="margin-top:12px">
      <div class="stat"><b class="mono" style="font-size:13px;word-break:break-all">${h(s.company)}</b><span>your company (hybrid keys, ${h(s.qor)})</span></div>
      <div class="stat"><b>${s.desk ? `InvoiceDeskV${s.version}` : "none yet"}</b><span>${s.desk ? `<a class="mono" href="https://explore.qore.network/address/${h(s.desk)}">${h(s.desk.slice(0, 12))}…</a>` : "run node desk.mjs setup"}</span></div>
      ${s.desk ? `<div class="stat"><b class="${s.agentOn ? "ok" : "no"}">${s.agentOn ? "ON" : "OFF"}</b><span>agent in the desk · key ${h(s.agentKey)}</span></div>
      <div class="stat"><b>${h(s.perPayment)} / ${h(s.daily)}</b><span>agent limits · ${h(s.leftToday)} left today</span></div>
      <div class="stat"><b>${h(s.float)}</b><span>float (ERC-20) · treasury ${h(s.treasury)}</span></div>` : ""}
    </div>${r.next ? `<p class="small">Next: <span class="mono">${h(r.next)}</span></p>` : ""}`;
    $("vlist").innerHTML = Object.keys(s.vendors).length ? `<table><tr><th>Vendor</th><th>Address</th><th></th></tr>${Object.entries(s.vendors).map(([a, n]) => `<tr><td>${h(n)}</td><td class="mono">${h(a)}</td><td><button data-rm="${h(a)}">Remove</button></td></tr>`).join("")}</table>` : `<span class="dim">No vendors approved yet.</span>`;
    $("vlist").querySelectorAll("[data-rm]").forEach((b) => (b.onclick = () => act(`remove vendor ${b.dataset.rm.slice(0, 10)}…`, "POST", `/vendor?do=remove&address=${b.dataset.rm}`)));
    $("mine").style.display = s.desk ? "" : "none";
  }
  $("lconnect").onclick = async () => { L.url = $("lurl").value.trim().replace(/\/$/, ""); L.token = $("ltok").value.trim(); $("lstat").innerHTML = '<span class="dim">connecting…</span>'; await refresh(); };
  if (hp.get("token")) $("lconnect").click();

  $("a-on").onclick = () => act("agent on", "POST", "/agent?do=on");
  $("a-off").onclick = () => act("agent off", "POST", "/agent?do=off");
  $("a-freeze").onclick = () => act("freeze", "POST", "/freeze");
  $("a-unfreeze").onclick = () => act("unfreeze", "POST", "/unfreeze");
  $("a-rotate").onclick = () => act("new agent signer (every signature the old one made is void)", "POST", "/signer");
  $("v-add").onclick = () => act("approve vendor", "POST", `/vendor?do=add&address=${encodeURIComponent($("vaddr").value.trim())}&name=${encodeURIComponent($("vname").value.trim() || "vendor")}`);
  $("v-pub").onclick = () => act("approve the public test vendor", "POST", `/vendor?do=add&address=${D.publicVendor.evm}&name=${encodeURIComponent("Public Test Vendor")}`);
  $("l-set").onclick = () => act("set limits", "POST", `/limits?per=${encodeURIComponent($("lper").value)}&daily=${encodeURIComponent($("lday").value)}`);
  $("t-set").onclick = () => act("treasury / float", "POST", `/treasury?float=${encodeURIComponent($("tfl").value)}`);

  // the public test vendor signs a real fUSD invoice for YOUR desk and company, in this tab
  const mldsa = () => new Promise((r, j) => { if (window.mldsa) return r(window.mldsa); document.addEventListener("mldsa", () => r(window.mldsa), { once: true }); setTimeout(() => j(new Error("the ML-DSA-87 module did not load")), 15000); });
  $("pref").value = "PTV-" + Math.random().toString(36).slice(2, 8).toUpperCase();
  const invoiceFor = async (forge) => {
    const m = await mldsa(), s = L.snap, vendor = E.getAddress(D.publicVendor.evm), ref = $("pref").value.trim() + (forge ? "-F" : "");
    const amount = E.parseUnits($("pamt").value.trim(), 6), id = E.keccak256(E.toUtf8Bytes(ref)), dueBy = Math.floor(Date.now() / 1000) + 30 * 86400;
    const msg = E.getBytes(E.AbiCoder.defaultAbiCoder().encode(["bytes32", "uint256", "address", "address", "address", "address", "uint256", "bytes32", "uint64"],
      [DOMAIN, D.chain.chainId, s.desk, s.companyEvm, vendor, D.fusd, amount, id, dueBy]));
    const sk = forge ? m.keygen().secretKey : E.getBytes(D.publicVendor.secretKey);
    const invoice = { v: 2, token: D.fusd, vendor, fusd: $("pamt").value.trim(), amount: amount.toString(), ref, id, dueBy, signature: E.hexlify(m.sign(msg, sk)) };
    return { from: forge ? "billing@public-vendor.example (forged)" : "billing@public-vendor.example", subject: `Invoice ${ref}`, body: forge ? "Signed with a key that is not the vendor's." : "Signed with ML-DSA-87 in the Desk Console.", invoice };
  };
  $("i-sign").onclick = async () => { const f = await invoiceFor(false); await act(`add ${f.invoice.ref} (signed in this tab)`, "POST", "/inbox", JSON.stringify(f)); $("pref").value = "PTV-" + Math.random().toString(36).slice(2, 8).toUpperCase(); };
  $("i-forge").onclick = async () => { const f = await invoiceFor(true); await act(`add ${f.invoice.ref} (forged)`, "POST", "/inbox", JSON.stringify(f)); };
  $("i-add").onclick = () => act("add the pasted invoice", "POST", "/inbox", $("ijson").value);
  const showTriage = (items) => {
    const cls = (v) => (v === "AGENT PAYS" ? "ok" : v === "REJECTED" ? "no" : "warn");
    $("tri").innerHTML = `<table style="margin-top:10px"><tr><th>#</th><th>Invoice</th><th>Amount</th><th>Verdict</th><th></th></tr>${items.map((x) => `<tr><td>${x.i}</td><td>${h(x.ref ?? "")}<br><span class="dim">${h(x.vendorName ?? "")}</span></td><td>${h(x.amount ?? "")}</td><td><b class="${cls(x.verdict)}">${h(x.verdict)}</b><br><span class="dim">${h(x.why)}</span></td><td>${x.verdict === "NEEDS A PERSON" ? `<button data-pay="${x.i}">Pay in person</button>` : ""}</td></tr>`).join("")}</table>`;
    $("tri").querySelectorAll("[data-pay]").forEach((b) => (b.onclick = async () => { await act(`pay #${b.dataset.pay} in person`, "POST", `/pay?n=${b.dataset.pay}`); $("i-triage").click(); }));
  };
  $("i-triage").onclick = async () => { const r = await act("triage", "GET", "/triage"); if (r?.ok) showTriage(r.value); };
  $("i-run").onclick = async () => { await act("the agent pays what triage allows", "POST", "/run"); $("i-triage").click(); };
  $("x-export").onclick = async () => {
    const r = await act("export", "GET", "/export");
    if (!r?.ok) return;
    const rows = r.value.trim().split("\n").map((l) => l.split(","));
    $("xout").innerHTML = `<table style="margin-top:10px">${rows.slice(0, 1).map((x) => `<tr>${[0, 1, 3, 5, 7].map((i) => `<th>${h(x[i])}</th>`).join("")}</tr>`).join("")}${rows.slice(1).reverse().slice(0, 15).map((x) => `<tr>${[0, 1, 3, 5, 7].map((i) => `<td>${h(x[i])}</td>`).join("")}</tr>`).join("")}</table>
      <a download="payments.csv" href="data:text/csv;charset=utf-8,${encodeURIComponent(r.value)}">Download payments.csv</a>`;
  };
})();
