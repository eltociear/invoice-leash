// Offline checks of the agent signer's guard (lib/agent.mjs wouldRefuse / signerMay), against a stand-in for
// the chain: an InvoiceDeskV4 whose state each case sets. No network. The guard must sign only a payment the
// desk would make now, or one it can never make, and must never sign when it cannot get an answer.
import { strict as assert } from "node:assert";
import { AbiCoder, Interface } from "ethers";
import { deskV4, signerMay, wouldRefuse, NEVER_PAYABLE } from "../lib/agent.mjs";

const PAYER = "0x1ad0909a70b4baa9deeffee606378665c5f83bb1", AGENT = "0x4e5bfe5f83cf722378a4c5f73fed9bf474c496b0";
const DESK = "0x235dA59171c8aa62fD5488f1870cE8ef1f420ac4", SIGNER = "0x3430d5a0000000000000000000000000000000aa";
const FUSD = "0x97143B771D34ddb9130b807b135Ae675A5a963CA", VENDOR = "0xCf115B0035C6432f315C21BA5BE128fE0E617374";
const d = { version: 4, invoiceDesk: DESK, payerEvm: PAYER, agentAccountEvm: AGENT };
const NOW = Date.parse("2026-11-25T12:00:00Z");
const inv = (o = {}) => ({ token: FUSD, vendor: VENDOR, amount: "4000000", id: "0x" + "11".repeat(32), dueBy: NOW / 1000 + 30 * 86400, signature: "0x1234", ...o });
const STATUS = new Interface(["function pqcKeyStatus(address) view returns (bool registered, uint8 algorithmId, bytes pubkey, bool possessionProven)"]);
const abi = AbiCoder.defaultAbiCoder();

// a stand-in for the chain: state -> answers, as ethers would surface them
function chain(state = {}) {
  const s = { isAgent: true, signer: SIGNER, key: [true, 1, "0xabcd", true], payerPay: null, perPayment: 10_000_000n, daily: 25_000_000n, remaining: 25_000_000n, down: false, ...state };
  const calls = [];
  return {
    calls,
    async call({ to, data, from }) {
      calls.push({ to, data, from });
      if (s.down) { const e = new Error("fetch failed"); e.code = "NETWORK_ERROR"; throw e; }
      if (to.toLowerCase() === "0x0000000000000000000000000000000000000a02") return STATUS.encodeFunctionResult("pqcKeyStatus", s.key);
      const f = deskV4.parseTransaction({ data });
      if (f.name === "isAgent") return abi.encode(["bool"], [s.isAgent]);
      if (f.name === "agentSigner") return abi.encode(["address"], [s.signer]);
      if (f.name === "limits") return abi.encode(["uint256", "uint256"], [s.perPayment, s.daily]);
      if (f.name === "remainingToday") return abi.encode(["uint256"], [s.remaining]);
      if (f.name === "pay") {
        assert.equal(from.toLowerCase(), PAYER, "the dry run is the company's own pay, not the agent's");
        assert.equal(f.args[7], "0x", "the dry run carries no agent signature");
        if (!s.payerPay) return "0x";
        const e = new Error("execution reverted"); e.shortMessage = "execution reverted"; e.data = deskV4.encodeErrorResult(s.payerPay[0], s.payerPay.slice(1)); throw e;
      }
      throw new Error(`unexpected call ${f.name}`);
    },
  };
}
const ask = (state, o) => { const provider = chain(state); return signerMay(d, inv(o), { provider, now: NOW }).then((r) => ({ ...r, provider })); };

let n = 0;
const t = async (name, fn) => { await fn(); n++; console.log(`ok   ${name}`); };

await t("signs a payment the desk would make now", async () => {
  const r = await ask();
  assert.deepEqual([r.sign, r.reason], [true, null]);
});
await t("no agent signature ever reaches the chain stand-in while asking", async () => {
  const { provider } = await ask();
  assert.ok(provider.calls.every((c) => !c.data.startsWith(deskV4.getFunction("pay").selector) || deskV4.parseTransaction({ data: c.data }).args[7] === "0x"));
});
for (const [name, state, o, reason] of [
  ["over today's limit (could pass tomorrow)", { remaining: 3_000_000n }, {}, "OverDailyLimit"],
  ["over the per-payment limit (the company could raise it)", {}, { amount: "15000000" }, "OverPerPaymentLimit"],
  ["a vendor not approved (the company could approve it)", { payerPay: ["UnknownVendor", VENDOR] }, {}, "UnknownVendor"],
  ["a float too low (the company could top it up)", { payerPay: ["TransferFailed"] }, {}, "TransferFailed"],
  ["the agent switched off (it could be switched on)", { isAgent: false }, {}, "NotPayersAgent"],
  ["no signer named", { signer: "0x0000000000000000000000000000000000000000" }, {}, "AgentSignerNotSet"],
  ["the signer's key not proven", { key: [true, 1, "0xabcd", false] }, {}, "AgentKeyNotProven"],
  ["due within ten minutes (it would be payable for a few minutes)", {}, { dueBy: NOW / 1000 + 300 }, "PastDue"],
]) await t(`declines: ${name}`, async () => {
  const r = await ask(state, o);
  assert.deepEqual([r.sign, r.reason], [false, reason]);
});
for (const [name, state, o, reason] of [
  ["a vendor signature that does not verify (a forgery, an edited copy)", { payerPay: ["BadSignature"] }, {}, "BadSignature"],
  ["already paid (a replay)", { payerPay: ["AlreadyPaid", "0x" + "11".repeat(32)] }, {}, "AlreadyPaid"],
  ["zero", { payerPay: ["ZeroAmount"] }, {}, "ZeroAmount"],
  ["native QOR (an agent may never pay it)", {}, { token: "0x0000000000000000000000000000000000000000" }, "AgentCannotPayNative"],
  ["already past due", {}, { dueBy: NOW / 1000 - 60 }, "PastDue"],
]) await t(`signs, since the desk can never pay it: ${name}`, async () => {
  const r = await ask(state, o);
  assert.deepEqual([r.sign, r.reason], [true, reason]);
});
await t("no answer from the chain: no signature (it throws, the caller signs nothing)", async () => {
  await assert.rejects(() => signerMay(d, inv(), { provider: chain({ down: true }), now: NOW }));
});
await t("the never-payable list is exactly the reasons no later action of the company undoes", () => {
  assert.deepEqual([...NEVER_PAYABLE].sort(), ["AgentCannotPayNative", "AlreadyPaid", "BadSignature", "ZeroAmount"]);
  for (const e of NEVER_PAYABLE) assert.ok(deskV4.getError(e), `${e} is one of InvoiceDeskV4's errors`);
});
await t("wouldRefuse reads the agent-only rules from the desk, not from the request", async () => {
  assert.equal(await wouldRefuse(d, inv({ amount: "11000000" }), { provider: chain(), now: NOW }), "OverPerPaymentLimit");
  assert.equal(await wouldRefuse(d, inv({ amount: "11000000" }), { provider: chain({ perPayment: 20_000_000n }), now: NOW }), null);
});
console.log(`✓ guard: ${n} checks of what the agent's signer will sign`);
