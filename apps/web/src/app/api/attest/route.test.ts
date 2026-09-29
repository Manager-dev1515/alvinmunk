// @vitest-environment node
/**
 * Tests for the /api/attest route handler.
 *
 * Two suites:
 *   - "status codes" (issue #180): every status-code branch of the handler itself —
 *     config, body size, rate limit, input validation, evidence shape/verification,
 *     signing, and the happy path (signature verified cryptographically).
 *   - "quest ↔ evidence binding" (issue #359 regression coverage): the handler must
 *     refuse to sign a quest id for any evidence type other than the one bound to it,
 *     and must do so before verifying anything over the network.
 *
 * Both suites share one mock of `@stellar/stellar-sdk` that replaces `rpc.Server` with
 * a stub exposing `simulateTransaction` / `getLatestLedger` / `getEvents` as plain
 * `vi.fn()`s — real Keypair/StrKey/nativeToScVal/etc. pass through unmocked so the
 * happy-path signature can be verified cryptographically.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Keypair, StrKey, nativeToScVal } from '@stellar/stellar-sdk';

/** A syntactically valid (properly checksummed) contract StrKey for env fixtures. */
function fakeContractId(fill: number): string {
  return StrKey.encodeContract(Buffer.alloc(32, fill));
}

// ─── shared test fixtures ────────────────────────────────────────────────────

// Real, checksum-valid addresses — a syntactically-shaped-but-fake StrKey (e.g. 'G' +
// 'A'.repeat(55)) fails `Address(...).toScVal()` with "Unsupported address type" once a
// request reaches real signing, so the happy-path / signing-failure tests below would
// never exercise the branch they claim to.
const G = Keypair.random().publicKey(); // valid G-address
const G2 = Keypair.random().publicKey(); // a second, distinct valid G-address
const C = fakeContractId(1); // valid C-address (passkey smart-wallet / contract)

/** Fake 32-byte payload the mock contract returns. */
const FAKE_PAYLOAD = Buffer.alloc(32, 0xab);

/** Real keypair used in the happy path so we can verify the signature. */
const ATTESTER_KP = Keypair.random();

// ─── RPC / Stellar mock (shared by both suites) ─────────────────────────────

const simulateMock = vi.fn();
const getLatestLedgerMock = vi.fn();
const getEventsMock = vi.fn();

vi.mock('@stellar/stellar-sdk', async (importOriginal) => {
  const real = await importOriginal<typeof import('@stellar/stellar-sdk')>();
  return {
    ...real,
    rpc: {
      ...real.rpc,
      Server: vi.fn().mockImplementation(() => ({
        simulateTransaction: simulateMock,
        getLatestLedger: getLatestLedgerMock,
        getEvents: getEventsMock,
      })),
      Api: real.rpc.Api,
    },
  };
});

// ══════════════════════════════════════════════════════════════════════════
// Suite 1 — status codes (issue #180)
// ══════════════════════════════════════════════════════════════════════════

/** Build a minimal Next.js-compatible Request with a JSON body. */
function makeRequest(
  body: unknown,
  opts: { ip?: string; contentLength?: number | null; bigBody?: boolean } = {},
): Request {
  const raw = opts.bigBody ? 'x'.repeat(5_000) : JSON.stringify(body);
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (opts.ip) headers['x-forwarded-for'] = opts.ip;
  if (opts.contentLength !== undefined && opts.contentLength !== null) {
    headers['content-length'] = String(opts.contentLength);
  }
  return new Request('http://localhost/api/attest', {
    method: 'POST',
    headers,
    body: raw,
  });
}

/** Import a fresh copy of the route (module-level state is reset). */
async function loadRoute() {
  const mod = await import('./route');
  return mod.POST;
}

// ─── base env every test starts from ─────────────────────────────────────────

function setBaseEnv() {
  process.env.ATTESTER_SECRET_KEY = ATTESTER_KP.secret();
  process.env.NEXT_PUBLIC_QUEST_REGISTRY_CONTRACT_ID = fakeContractId(9);
  process.env.NEXT_PUBLIC_RPC_URL = 'https://soroban-testnet.stellar.org';
  process.env.NEXT_PUBLIC_HORIZON_URL = 'https://horizon-testnet.stellar.org';
  process.env.NEXT_PUBLIC_STELLAR_NETWORK = 'testnet';
  delete process.env.QUEST_GITHUB_REPOS;
  delete process.env.GITHUB_TOKEN;
  delete process.env.NEXT_PUBLIC_REPUTATION_CONTRACT_ID;
  // Quest ↔ evidence binding (lib/attest.ts buildQuestEvidenceMap). Left unset so
  // DEFAULT_QUEST_IDS applies: referral_tx→2, invite_converts→3, vouch_back→4;
  // github_pr stays unmapped unless a test opts in via QUEST_GITHUB_ID below. Deleted
  // (not just left alone) so a value set by one test can never leak into the next.
  delete process.env.QUEST_GITHUB_ID;
  delete process.env.NEXT_PUBLIC_DEFAULT_QUEST_ID;
  delete process.env.NEXT_PUBLIC_INVITE_QUEST_ID;
  delete process.env.NEXT_PUBLIC_VOUCHBACK_QUEST_ID;
}

/** Default simulateTransaction for the quest_payload call — returns FAKE_PAYLOAD. */
function setupPayloadSim() {
  const retval = nativeToScVal(FAKE_PAYLOAD);
  simulateMock.mockResolvedValue({ result: { retval } });
}

describe('POST /api/attest — status codes (issue #180)', () => {
  beforeEach(() => {
    vi.resetModules();
    setBaseEnv();
    simulateMock.mockReset();
    getLatestLedgerMock.mockReset();
    getEventsMock.mockReset();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ── 500: attester not configured ─────────────────────────────────────────

  it('500 when ATTESTER_SECRET_KEY is missing', async () => {
    delete process.env.ATTESTER_SECRET_KEY;
    const POST = await loadRoute();
    const res = await POST(makeRequest({ questId: 1, recipient: G }));
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/not configured/i);
  });

  it('500 when quest registry contract id is missing', async () => {
    process.env.NEXT_PUBLIC_QUEST_REGISTRY_CONTRACT_ID = '';
    const POST = await loadRoute();
    const res = await POST(makeRequest({ questId: 1, recipient: G }));
    expect(res.status).toBe(500);
  });

  // ── 413: body size ────────────────────────────────────────────────────────

  it('413 when content-length header exceeds MAX_BODY_BYTES', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({}, { contentLength: 5_000 }));
    expect(res.status).toBe(413);
  });

  it('413 when chunked body (no content-length) exceeds MAX_BODY_BYTES', async () => {
    const POST = await loadRoute();
    // No content-length header; raw body is 5 000 bytes
    const req = new Request('http://localhost/api/attest', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '1.2.3.4' },
      body: 'x'.repeat(5_000),
    });
    const res = await POST(req);
    expect(res.status).toBe(413);
  });

  // ── 429: rate limit ───────────────────────────────────────────────────────

  it('429 on the 7th request from the same IP within 60 s', async () => {
    const POST = await loadRoute();
    // First 6 should pass (may fail downstream, but status won't be 429).
    for (let i = 0; i < 6; i++) {
      const res = await POST(makeRequest({ questId: 1, recipient: G }, { ip: '5.5.5.5' }));
      expect(res.status).not.toBe(429);
    }
    // 7th must be rate-limited.
    const res = await POST(makeRequest({ questId: 1, recipient: G }, { ip: '5.5.5.5' }));
    expect(res.status).toBe(429);
  });

  it('rate-limit is per-IP — a different IP is not affected', async () => {
    const POST = await loadRoute();
    for (let i = 0; i < 7; i++) {
      await POST(makeRequest({ questId: 1, recipient: G }, { ip: '6.6.6.6' }));
    }
    // Different IP still gets through (400 for bad input, not 429).
    const res = await POST(makeRequest({ questId: 1, recipient: G }, { ip: '7.7.7.7' }));
    expect(res.status).not.toBe(429);
  });

  // ── 400: invalid JSON ─────────────────────────────────────────────────────

  it('400 on invalid JSON body', async () => {
    const POST = await loadRoute();
    const req = new Request('http://localhost/api/attest', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not valid json',
    });
    const res = await POST(req);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/json/i);
  });

  // ── 400: bad questId / recipient ─────────────────────────────────────────

  it('400 when questId is missing', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({ recipient: G }));
    expect(res.status).toBe(400);
  });

  it('400 when questId is a float', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({ questId: 1.5, recipient: G }));
    expect(res.status).toBe(400);
  });

  it('400 when questId is negative', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({ questId: -1, recipient: G }));
    expect(res.status).toBe(400);
  });

  it('400 when recipient is not a G/C address', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({ questId: 1, recipient: 'notanaddress' }));
    expect(res.status).toBe(400);
  });

  it('400 when recipient is missing', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({ questId: 1 }));
    expect(res.status).toBe(400);
  });

  // ── 422: evidence shape ───────────────────────────────────────────────────

  it('422 when evidence type is unknown', async () => {
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({ questId: 1, recipient: G, evidence: { type: 'nope', ref: 'x' } }),
    );
    expect(res.status).toBe(422);
  });

  it('422 when github_pr ref format is wrong', async () => {
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 1,
        recipient: G,
        evidence: { type: 'github_pr', ref: 'not-a-pr-ref' },
      }),
    );
    expect(res.status).toBe(422);
  });

  it('422 when referral_tx ref is not a G-address', async () => {
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 2,
        recipient: G,
        evidence: { type: 'referral_tx', ref: 'NOTANADDRESS' },
      }),
    );
    expect(res.status).toBe(422);
  });

  it('422 when referral_tx is a self-referral', async () => {
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 2,
        recipient: G,
        evidence: { type: 'referral_tx', ref: G },
      }),
    );
    expect(res.status).toBe(422);
  });

  // ── 422: evidence verification — github_pr ────────────────────────────────
  // github_pr has no DEFAULT_QUEST_IDS entry (lib/attest.ts), so these bind it to
  // quest 1 via QUEST_GITHUB_ID before loading the route — otherwise the quest ↔
  // evidence binding check (added for issue #359) would reject at 422 before ever
  // reaching verifyEvidence, and the assertions below would never be exercised.

  it('422 when github repo is not on the allowlist', async () => {
    process.env.QUEST_GITHUB_ID = '1';
    process.env.QUEST_GITHUB_REPOS = 'allowed/repo';
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 1,
        recipient: G,
        evidence: { type: 'github_pr', ref: 'evil/repo#1' },
      }),
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/not eligible/i);
  });

  it('422 when PR is not merged', async () => {
    process.env.QUEST_GITHUB_ID = '1';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ merged: false }),
      }),
    );
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 1,
        recipient: G,
        evidence: { type: 'github_pr', ref: 'owner/repo#42' },
      }),
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/not merged/i);
  });

  it('422 when GitHub API returns non-200', async () => {
    process.env.QUEST_GITHUB_ID = '1';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404 }));
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 1,
        recipient: G,
        evidence: { type: 'github_pr', ref: 'owner/repo#99' },
      }),
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/github 404/i);
  });

  // ── 422: evidence verification — referral_tx ──────────────────────────────
  // referral_tx defaults to quest 2 (DEFAULT_QUEST_IDS.referral_tx in lib/attest.ts),
  // so these use questId 2 to clear the quest ↔ evidence binding check.

  it('422 when referred account is not found on Horizon (404)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404 }));
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 2,
        recipient: G,
        evidence: { type: 'referral_tx', ref: G2 },
      }),
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/not found/i);
  });

  it('422 when referred account has no referral marker', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ data: {} }), // no "referral" key
      }),
    );
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 2,
        recipient: G,
        evidence: { type: 'referral_tx', ref: G2 },
      }),
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/no "referral" data entry/i);
  });

  it('422 when referral marker points to a different referrer', async () => {
    const someoneElse = 'G' + 'C'.repeat(55);
    const encoded = Buffer.from(someoneElse, 'utf8').toString('base64');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ data: { referral: encoded } }),
      }),
    );
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 2,
        recipient: G,
        evidence: { type: 'referral_tx', ref: G2 },
      }),
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/different referrer/i);
  });

  it('422 when referral marker is a self-referral on the referred account', async () => {
    // marker stores G2 (the ref / referred address) but recipient is G
    // stored === ev.ref triggers the self-referral branch
    const encoded = Buffer.from(G2, 'utf8').toString('base64');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ data: { referral: encoded } }),
      }),
    );
    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 2,
        recipient: G,
        evidence: { type: 'referral_tx', ref: G2 },
      }),
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/self-referral/i);
  });

  // ── 502: signing failure ──────────────────────────────────────────────────

  it('502 when simulateTransaction returns a simulation error', async () => {
    process.env.QUEST_GITHUB_ID = '1';
    // Pass evidence verification (github_pr, merged PR).
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ merged: true }),
      }),
    );
    // But payload simulation fails.
    simulateMock.mockResolvedValue({ error: 'contract panic' });

    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 1,
        recipient: G,
        evidence: { type: 'github_pr', ref: 'owner/repo#1' },
      }),
    );
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: string };
    expect(body.error).toMatch(/payload read failed/i);
  });

  it('502 when simulateTransaction throws', async () => {
    process.env.QUEST_GITHUB_ID = '1';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ merged: true }),
      }),
    );
    simulateMock.mockRejectedValue(new Error('rpc timeout'));

    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 1,
        recipient: G,
        evidence: { type: 'github_pr', ref: 'owner/repo#1' },
      }),
    );
    expect(res.status).toBe(502);
  });

  // ── 200: happy path — github_pr, signature verified ───────────────────────

  it('200 with valid github_pr evidence — returned sig verifies over the mocked payload', async () => {
    process.env.QUEST_GITHUB_ID = '5';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ merged: true }),
      }),
    );
    setupPayloadSim();

    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 5,
        recipient: G,
        evidence: { type: 'github_pr', ref: 'owner/repo#7' },
      }),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      attester: string;
      sig: string;
      recipient: string;
      questId: number;
    };

    expect(body.ok).toBe(true);
    expect(body.recipient).toBe(G);
    expect(body.questId).toBe(5);

    // Cryptographic verification: rebuild the keypair from the public key the
    // route returned, then verify the sig over the known fake payload.
    const attesterPub = Buffer.from(body.attester, 'hex');
    const kp = Keypair.fromRawEd25519Seed(ATTESTER_KP.rawSecretKey());
    expect(kp.rawPublicKey().toString('hex')).toBe(body.attester);

    const sigBytes = Buffer.from(body.sig, 'base64');
    expect(() => kp.verify(FAKE_PAYLOAD, sigBytes)).not.toThrow();
    expect(kp.verify(FAKE_PAYLOAD, sigBytes)).toBe(true);

    // A tampered payload must NOT verify.
    const tampered = Buffer.from(FAKE_PAYLOAD);
    tampered[0] ^= 0xff;
    expect(kp.verify(tampered, sigBytes)).toBe(false);

    void attesterPub; // used indirectly via kp
  });

  // ── 200: happy path — referral_tx, C-address recipient ───────────────────

  it('200 with valid referral_tx evidence and a C-address recipient', async () => {
    const encoded = Buffer.from(C, 'utf8').toString('base64'); // marker value = recipient
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ data: { referral: encoded } }),
      }),
    );
    setupPayloadSim();

    const POST = await loadRoute();
    const res = await POST(
      makeRequest({
        questId: 2,
        recipient: C,
        evidence: { type: 'referral_tx', ref: G2 },
      }),
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; recipient: string };
    expect(body.ok).toBe(true);
    expect(body.recipient).toBe(C);
  });

  // ── rate-limit sweep (hits.size > 500) ────────────────────────────────────

  it('sweep runs without crashing when the hits map exceeds 500 entries', async () => {
    const POST = await loadRoute();
    // Fire requests from 501 distinct IPs to force the sweep branch.
    const promises: Promise<Response>[] = [];
    for (let i = 0; i < 501; i++) {
      promises.push(
        POST(
          makeRequest(
            { questId: 1, recipient: G },
            { ip: `10.0.${Math.floor(i / 256)}.${i % 256}` },
          ),
        ),
      );
    }
    const responses = await Promise.all(promises);
    // None should be 429 (each IP has only 1 hit).
    for (const r of responses) expect(r.status).not.toBe(429);
  });
});

// ══════════════════════════════════════════════════════════════════════════
// Suite 2 — quest ↔ evidence binding (issue #359 regression coverage)
// ══════════════════════════════════════════════════════════════════════════
// POST /api/attest must refuse to sign a quest id for any evidence type other than the one
// bound to it, and must do so before verifying anything over the network.

describe('POST /api/attest quest ↔ evidence binding', () => {
  const RECIPIENT = Keypair.random().publicKey();
  const REFERRED = Keypair.random().publicKey();
  const QUEST_CONTRACT = StrKey.encodeContract(Buffer.alloc(32, 7));

  type Post = (req: Request) => Promise<Response>;
  let POST: Post;
  let fetchSpy: ReturnType<typeof vi.fn>;

  function attest(body: Record<string, unknown>): Promise<Response> {
    return POST(
      new Request('http://localhost/api/attest', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.9' },
        body: JSON.stringify({ recipient: RECIPIENT, ...body }),
      }),
    );
  }

  beforeEach(async () => {
    vi.resetModules();
    simulateMock.mockReset();
    getLatestLedgerMock.mockReset();
    getEventsMock.mockReset();
    vi.stubEnv('ATTESTER_SECRET_KEY', Keypair.random().secret());
    vi.stubEnv('NEXT_PUBLIC_QUEST_REGISTRY_CONTRACT_ID', QUEST_CONTRACT);
    vi.stubEnv('NEXT_PUBLIC_REPUTATION_CONTRACT_ID', QUEST_CONTRACT);
    // The dashboard defaults: 2 = referral_tx, 3 = invite_converts, 4 = vouch_back; no GitHub quest.
    vi.stubEnv('NEXT_PUBLIC_DEFAULT_QUEST_ID', '');
    vi.stubEnv('NEXT_PUBLIC_INVITE_QUEST_ID', '');
    vi.stubEnv('NEXT_PUBLIC_VOUCHBACK_QUEST_ID', '');
    vi.stubEnv('QUEST_GITHUB_ID', '');
    fetchSpy = vi.fn(async () => new Response('{}', { status: 404 }));
    vi.stubGlobal('fetch', fetchSpy);
    ({ POST } = (await import('./route')) as { POST: Post });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  function expectNoNetwork() {
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(simulateMock).not.toHaveBeenCalled();
    expect(getLatestLedgerMock).not.toHaveBeenCalled();
  }

  it('rejects vouch_back evidence replayed against the 50 XP quests, before any network call', async () => {
    for (const questId of [1, 3]) {
      const res = await attest({ questId, evidence: { type: 'vouch_back', ref: '' } });
      expect(res.status).toBe(422);
      const body = (await res.json()) as { error: string; sig?: string };
      expect(body.sig).toBeUndefined();
    }
    expectNoNetwork();
  });

  it('rejects a mismatched type with 422 and names the mismatch', async () => {
    const res = await attest({ questId: 3, evidence: { type: 'referral_tx', ref: REFERRED } });
    expect(res.status).toBe(422);
    expect(await res.json()).toEqual({ error: 'evidence type does not match this quest' });
    expectNoNetwork();
  });

  it('rejects a quest id with no mapping, including github_pr while QUEST_GITHUB_ID is unset', async () => {
    const unmapped = await attest({
      questId: 99,
      evidence: { type: 'referral_tx', ref: REFERRED },
    });
    expect(unmapped.status).toBe(422);
    expect(await unmapped.json()).toEqual({ error: 'this quest cannot be attested' });
    const github = await attest({ questId: 1, evidence: { type: 'github_pr', ref: 'o/r#1' } });
    expect(github.status).toBe(422);
    expectNoNetwork();
  });

  it('lets the bound type through to verification', async () => {
    const res = await attest({ questId: 2, evidence: { type: 'referral_tx', ref: REFERRED } });
    expect(res.status).toBe(422);
    expect(await res.json()).toEqual({ error: 'referred account not found on-chain' });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(String(fetchSpy.mock.calls[0][0])).toContain(`/accounts/${REFERRED}`);
  });

  it('signs the bound quest once its evidence verifies', async () => {
    const marker = Buffer.from(RECIPIENT, 'utf8').toString('base64');
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify({ data: { referral: marker } }), { status: 200 }),
    );
    simulateMock.mockResolvedValueOnce({
      result: { retval: nativeToScVal(Buffer.from('payload')) },
    });
    const res = await attest({ questId: 2, evidence: { type: 'referral_tx', ref: REFERRED } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; questId: number; sig: string };
    expect(body.ok).toBe(true);
    expect(body.questId).toBe(2);
    expect(body.sig).toBeTruthy();
  });

  it('binds a quest id configured in env, not its default', async () => {
    vi.resetModules();
    vi.stubEnv('QUEST_GITHUB_ID', '1');
    vi.stubEnv('NEXT_PUBLIC_VOUCHBACK_QUEST_ID', '5');
    ({ POST } = (await import('./route')) as { POST: Post });
    // quest 4 is no longer the vouch_back quest
    const res = await attest({ questId: 4, evidence: { type: 'vouch_back', ref: '' } });
    expect(res.status).toBe(422);
    expectNoNetwork();
    // github_pr is now attestable on quest 1 (the GitHub API is reached)
    const gh = await attest({ questId: 1, evidence: { type: 'github_pr', ref: 'o/r#1' } });
    expect(gh.status).toBe(422);
    expect(await gh.json()).toEqual({ error: 'github 404' });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
