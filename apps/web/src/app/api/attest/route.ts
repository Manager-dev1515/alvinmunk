/**
 * Serverless ATTESTER (no standing backend — 00-strategy). Holds the allowlisted attester
 * secret (server-only ATTESTER_SECRET_KEY), VERIFIES a real action, then returns its
 * ed25519 SIGNATURE over the quest_registry's canonical payload. It does NOT submit a tx:
 * the wallet submits `award_quest` itself, proving ownership on-chain via
 * `recipient.require_auth()`. The attester pubkey must be allowlisted via
 * `quest_registry.add_attester_key`.
 *
 * Only cryptographically / API-verifiable quests are accepted (00-strategy §1):
 *   - github_pr   : evidence.ref = "owner/repo#123" -> PR must be merged
 *   - referral_tx : evidence.ref = "G..." address   -> must have ≥1 on-chain tx
 *
 * Defense-in-depth (belts/08 §security): on-chain recipient.require_auth() ownership +
 * on-chain replay guard (the hard cap), per-IP rate limit, bounded body, optional GitHub
 * repo allowlist, self-referral guard. The signature is only redeemable by the recipient
 * (they must satisfy require_auth), so issuing it carries no transfer of funds.
 */
import {
  Account,
  Address,
  Contract,
  Keypair,
  Networks,
  TransactionBuilder,
  nativeToScVal,
  scValToNative,
  rpc,
} from '@stellar/stellar-sdk';
import {
  MAX_BODY_BYTES,
  REFERRAL_MARKER_KEY,
  VOUCH_BACK_MIN,
  decodeDataEntry,
  isValidQuestId,
  parseRepoAllowlist,
  repoAllowed,
  validateEvidence,
  type AttestEvidence,
} from '../../../lib/attest';

export const runtime = 'nodejs';

interface AttestRequest {
  questId: number;
  recipient: string;
  evidence?: AttestEvidence;
}

const RATE_MAX = 6; // requests per window per IP
const RATE_WINDOW_MS = 60_000;
const hits = new Map<string, { n: number; resetAt: number }>();

function rateLimited(ip: string, now: number): boolean {
  if (hits.size > 500) {
    for (const [k, v] of hits) if (now > v.resetAt) hits.delete(k);
  }
  const h = hits.get(ip);
  if (!h || now > h.resetAt) {
    hits.set(ip, { n: 1, resetAt: now + RATE_WINDOW_MS });
    return false;
  }
  h.n += 1;
  return h.n > RATE_MAX;
}

const RPC_URL = process.env.NEXT_PUBLIC_RPC_URL ?? 'https://soroban-testnet.stellar.org';
const HORIZON = process.env.NEXT_PUBLIC_HORIZON_URL ?? 'https://horizon-testnet.stellar.org';
const PASSPHRASE =
  process.env.NEXT_PUBLIC_STELLAR_NETWORK === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;
const QUEST_ID = process.env.NEXT_PUBLIC_QUEST_REGISTRY_CONTRACT_ID ?? '';
const REP_ID = process.env.NEXT_PUBLIC_REPUTATION_CONTRACT_ID ?? '';
const REPO_ALLOWLIST = parseRepoAllowlist(process.env.QUEST_GITHUB_REPOS);
/** Safety cap on cursor-pagination pages for the vouch/claimed scan (1 000 events/page). */
const VOUCH_CLAIMED_MAX_PAGES = 50;

// Recipient may be a classic (G…) OR a passkey smart-account (C…) address.
const STELLAR_ADDRESS = /^[GC][A-Z2-7]{55}$/;

export async function POST(req: Request): Promise<Response> {
  const secret = process.env.ATTESTER_SECRET_KEY;
  if (!secret || !QUEST_ID) {
    return json({ error: 'attester not configured (ATTESTER_SECRET_KEY / quest id)' }, 500);
  }

  const len = Number(req.headers.get('content-length') ?? '0');
  if (Number.isFinite(len) && len > MAX_BODY_BYTES) {
    return json({ error: 'request too large' }, 413);
  }

  const now = Date.now();
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  if (rateLimited(ip, now)) return json({ error: 'rate limited, slow down' }, 429);

  let raw: string;
  try {
    raw = await req.text();
  } catch {
    return json({ error: 'invalid body' }, 400);
  }
  if (raw.length > MAX_BODY_BYTES) return json({ error: 'request too large' }, 413);

  let body: AttestRequest;
  try {
    body = JSON.parse(raw) as AttestRequest;
  } catch {
    return json({ error: 'invalid json' }, 400);
  }
  if (!isValidQuestId(body.questId) || !STELLAR_ADDRESS.test(body.recipient ?? '')) {
    return json({ error: 'questId (number) and recipient (G/C address) required' }, 400);
  }

  // 1) Evidence shape (cheap, network-free) — format, length, self-referral.
  const shape = validateEvidence(body.evidence, body.recipient);
  if (!shape.ok) return json({ error: shape.reason }, 422);

  // 2) Verify the real-world action (network).
  const verified = await verifyEvidence(body.evidence as AttestEvidence, body.recipient);
  if (!verified.ok) return json({ error: verified.reason }, 422);

  // 3) Sign the contract's canonical payload — the recipient redeems it on-chain.
  try {
    const signed = await signQuestPayload(secret, body.questId, body.recipient);
    logEvent({ route: 'attest', outcome: 'ok', questId: body.questId, ms: Date.now() - now });
    return json({ ok: true, ...signed, recipient: body.recipient, questId: body.questId });
  } catch (e) {
    logEvent({ route: 'attest', outcome: 'error', questId: body.questId, ms: Date.now() - now });
    return json({ error: e instanceof Error ? e.message : 'sign failed' }, 502);
  }
}

function logEvent(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ t: new Date().toISOString(), ...fields }));
}

async function verifyEvidence(
  ev: AttestEvidence,
  recipient: string,
): Promise<{ ok: boolean; reason?: string }> {
  // Invite-converts (growth quest): the person you invited has opened a profile AND been
  // vouched for — i.e. their Social score is > 0. Verified by reading the Reputation contract.
  if (ev.type === 'invite_converts') {
    if (!REP_ID) return { ok: false, reason: 'reputation contract not configured' };
    try {
      const score = await readU64(REP_ID, 'get_score', ev.ref);
      return score > 0n
        ? { ok: true }
        : { ok: false, reason: "that wallet hasn't been vouched for yet — invite them to claim a vouch first" };
    } catch {
      return { ok: false, reason: "couldn't read the invited wallet's reputation" };
    }
  }

  // Vouch-back (retention quest): you have vouched for >= VOUCH_BACK_MIN distinct people.
  //
  // Fix (#165): count distinct CLAIMERS from `vouch/claimed` events where `from` is the
  // recipient — not minted IDs from `vouch/minted`. A minted vouch is only a bearer link
  // that may never be redeemed; the quest promises "vouch for 3 people", which requires a
  // claim. Scan from the RPC's actual oldestLedger so vouches made earlier in the week are
  // not invisible, and follow the cursor until exhausted.
  if (ev.type === 'vouch_back') {
    if (!REP_ID) return { ok: false, reason: 'reputation contract not configured' };
    try {
      const n = await countVouchesClaimedBy(REP_ID, recipient);
      return n >= VOUCH_BACK_MIN
        ? { ok: true }
        : { ok: false, reason: `vouch for ${VOUCH_BACK_MIN} people first (${n} claimed so far)` };
    } catch {
      return { ok: false, reason: "couldn't read your vouch history right now — try again" };
    }
  }

  if (ev.type === 'github_pr') {
    const m = ev.ref.match(/^([\w.-]+)\/([\w.-]+)#(\d+)$/);
    if (!m) return { ok: false, reason: 'ref must be owner/repo#number' };
    const [, owner, repo, num] = m;
    if (!repoAllowed(REPO_ALLOWLIST, owner, repo)) {
      return { ok: false, reason: 'repo not eligible for this quest' };
    }
    const headers: Record<string, string> = { accept: 'application/vnd.github+json' };
    if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${num}`, {
      headers,
    });
    if (!r.ok) return { ok: false, reason: `github ${r.status}` };
    const pr = (await r.json()) as { merged?: boolean };
    return pr.merged ? { ok: true } : { ok: false, reason: 'PR not merged' };
  }

  if (ev.type === 'referral_tx') {
    // Fetch the referred account object (includes manageData under .data).
    const r = await fetch(`${HORIZON}/accounts/${ev.ref}`);
    if (r.status === 404) return { ok: false, reason: 'referred account not found on-chain' };
    if (!r.ok) return { ok: false, reason: `horizon error ${r.status}` };

    const acct = (await r.json()) as { data?: Record<string, string> };

    // The referred account MUST have set a manageData entry ("referral") whose value
    // (base64-decoded UTF-8) is exactly the referrer's address. This proves the referrer
    // caused the relationship — not merely that the referred account is active.
    const raw = acct.data?.[REFERRAL_MARKER_KEY];
    if (!raw) {
      return {
        ok: false,
        reason:
          `referred account has no "${REFERRAL_MARKER_KEY}" data entry — ` +
          'ask them to set it to your address during onboarding',
      };
    }

    const stored = decodeDataEntry(raw);
    if (stored !== recipient) {
      // Either corrupted, or someone tried to reuse a marker already claimed by
      // another referrer. Both cases are rejected.
      return {
        ok: false,
        reason:
          stored === ev.ref
            ? 'referral marker is a self-referral on the referred account'
            : 'referral marker points to a different referrer — cannot reuse this marker',
      };
    }

    return { ok: true };
  }

  return { ok: false, reason: 'unknown evidence type' };
}

/** Read a u64-returning view (e.g. get_score) via simulation — no fee, no signature. */
async function readU64(contractId: string, method: string, addr: string): Promise<bigint> {
  const server = new rpc.Server(RPC_URL, { allowHttp: RPC_URL.startsWith('http://') });
  const source = new Account(Keypair.random().publicKey(), '0');
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: PASSPHRASE })
    .addOperation(new Contract(contractId).call(method, new Address(addr).toScVal()))
    .setTimeout(30)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(sim.error);
  const v = sim.result?.retval;
  return v ? BigInt(scValToNative(v) as number | bigint) : 0n;
}

/**
 * A decoded `vouch/claimed` event value: (vouch_id, from, claimer).
 * Mirrors contracts/reputation/src/lib.rs claim_vouch emit at line ~293.
 */
export interface VouchClaimedEvent {
  vouchId: string; // stringified u64
  from: string;    // G/C address — the voucher
  claimer: string; // G/C address — the person who claimed
}

/**
 * Decode one raw `vouch/claimed` event value (a 3-tuple ScVal) into a typed record.
 * Returns null for any event that cannot be decoded — callers skip those silently.
 * Exported so it can be unit-tested independently of the RPC layer.
 */
export function decodeVouchClaimedEvent(
  raw: unknown, // scValToNative output for one event's value
): VouchClaimedEvent | null {
  if (!Array.isArray(raw) || raw.length !== 3) return null;
  const [id, from, claimer] = raw;
  if (
    (typeof id !== 'number' && typeof id !== 'bigint') ||
    typeof from !== 'string' ||
    typeof claimer !== 'string'
  ) {
    return null;
  }
  return { vouchId: String(id), from, claimer };
}

/**
 * Count distinct people `from` has successfully vouched for by scanning `vouch/claimed`
 * events across the RPC's full retention window (from `getHealth().oldestLedger`),
 * following the cursor until exhausted so no page is dropped.
 *
 * Fix for #165:
 *  - Uses `vouch/claimed` (not `vouch/minted`) — only redeemed vouches count.
 *  - Starts from `oldestLedger` (not `latestLedger - 9000`) for full history.
 *  - Paginates with cursor until the RPC signals the scan is complete.
 *  - Pure counting logic lives in `decodeVouchClaimedEvent` and is unit-tested separately.
 */
async function countVouchesClaimedBy(repId: string, from: string): Promise<number> {
  const server = new rpc.Server(RPC_URL, { allowHttp: RPC_URL.startsWith('http://') });

  // Start from the oldest ledger the RPC has retained — covers the full history.
  const health = await server.getHealth();
  const startLedger = health.oldestLedger ?? 1;

  // Topic filter: (`vouch`, `claimed`) — only claimed vouches, not mints or slashes.
  const t0 = nativeToScVal('vouch',   { type: 'symbol' }).toXDR('base64');
  const t1 = nativeToScVal('claimed', { type: 'symbol' }).toXDR('base64');
  const filters = [{ type: 'contract' as const, contractIds: [repId], topics: [[t0, t1]] }];

  const claimers = new Set<string>();
  let cursor: string | undefined;

  for (let page = 0; page < VOUCH_CLAIMED_MAX_PAGES; page++) {
    const res = await server.getEvents(
      cursor
        ? { filters, cursor, limit: 1000 }
        : { filters, startLedger, limit: 1000 },
    );

    for (const e of res.events) {
      const decoded = decodeVouchClaimedEvent(scValToNative(e.value));
      // Count each distinct claimer once — a re-claim of the same vouch (impossible
      // on-chain but defensive) would still be a unique claimer address.
      if (decoded && decoded.from === from) {
        claimers.add(decoded.claimer);
      }
    }

    cursor = res.cursor;
    if (!cursor) break; // RPC signals the scan is complete
  }

  return claimers.size;
}

/**
 * Read the contract's canonical payload (so we sign EXACTLY what it verifies — no
 * byte-mismatch risk) and ed25519-sign it with the attester key.
 */
async function signQuestPayload(
  secret: string,
  questId: number,
  recipient: string,
): Promise<{ attester: string; sig: string }> {
  const kp = Keypair.fromSecret(secret);
  const server = new rpc.Server(RPC_URL, { allowHttp: RPC_URL.startsWith('http://') });
  const source = new Account(Keypair.random().publicKey(), '0');
  const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: PASSPHRASE })
    .addOperation(
      new Contract(QUEST_ID).call(
        'quest_payload',
        nativeToScVal(questId, { type: 'u32' }),
        new Address(recipient).toScVal(),
      ),
    )
    .setTimeout(30)
    .build();

  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) {
    throw new Error(`payload read failed: ${sim.error}`);
  }
  const retval = sim.result?.retval;
  if (!retval) throw new Error('payload read returned nothing');
  const payload = scValToNative(retval) as Uint8Array;
  const sig = kp.sign(Buffer.from(payload));
  return { attester: kp.rawPublicKey().toString('hex'), sig: sig.toString('base64') };
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
