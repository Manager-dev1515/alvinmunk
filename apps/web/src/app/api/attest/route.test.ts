// @vitest-environment node
/**
 * Tests for the /api/attest route handler — issue #180.
 *
 * Every status-code branch is exercised:
 *   500  attester not configured
 *   413  body too large (content-length header / chunked oversize body)
 *   429  rate limit exceeded
 *   400  invalid JSON / bad questId or recipient
 *   422  bad evidence shape / failed verification
 *   502  signing failure
 *   200  happy path — signature is verified cryptographically
 *
 * Strategy:
 *   - `hits` and `REPO_ALLOWLIST` live at module scope, so env vars are set
 *     BEFORE each import and vi.resetModules() is called to get a fresh module.
 *   - fetch is stubbed with vi.stubGlobal so no real HTTP calls are made.
 *   - rpc.Server is mocked so simulateTransaction returns a controlled payload.
 *   - The happy-path keypair is a real Keypair generated here; we assert the
 *     returned sig verifies over the mocked payload bytes.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Keypair, nativeToScVal } from '@stellar/stellar-sdk';

// ─── shared test fixtures ────────────────────────────────────────────────────

const G = 'G' + 'A'.repeat(55); // valid G-address shape
const G2 = 'G' + 'B'.repeat(55);
const C = 'C' + 'A'.repeat(55); // valid C-address (passkey wallet)

/** Fake 32-byte payload the mock contract returns. */
const FAKE_PAYLOAD = Buffer.alloc(32, 0xab);

/** Real keypair used in the happy path so we can verify the signature. */
const ATTESTER_KP = Keypair.random();

// ─── RPC / Stellar mock ──────────────────────────────────────────────────────

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

// ─── helpers ─────────────────────────────────────────────────────────────────

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
  process.env.NEXT_PUBLIC_QUEST_REGISTRY_CONTRACT_ID = 'CQUESTID' + 'A'.repeat(48);
  process.env.NEXT_PUBLIC_RPC_URL = 'https://soroban-testnet.stellar.org';
  process.env.NEXT_PUBLIC_HORIZON_URL = 'https://horizon-testnet.stellar.org';
  process.env.NEXT_PUBLIC_STELLAR_NETWORK = 'testnet';
  delete process.env.QUEST_GITHUB_REPOS;
  delete process.env.GITHUB_TOKEN;
  delete process.env.NEXT_PUBLIC_REPUTATION_CONTRACT_ID;
}

/** Default simulateTransaction for the quest_payload call — returns FAKE_PAYLOAD. */
function setupPayloadSim() {
  const retval = nativeToScVal(FAKE_PAYLOAD);
  simulateMock.mockResolvedValue({ result: { retval } });
}

// ─── tests ────────────────────────────────────────────────────────────────────

describe('POST /api/attest', () => {
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
    const body = await res.json() as { error: string };
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
    const body = await res.json() as { error: string };
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
    const res = await POST(makeRequest({ questId: 1, recipient: G, evidence: { type: 'nope', ref: 'x' } }));
    expect(res.status).toBe(422);
  });

  it('422 when github_pr ref format is wrong', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'github_pr', ref: 'not-a-pr-ref' },
    }));
    expect(res.status).toBe(422);
  });

  it('422 when referral_tx ref is not a G-address', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'referral_tx', ref: 'NOTANADDRESS' },
    }));
    expect(res.status).toBe(422);
  });

  it('422 when referral_tx is a self-referral', async () => {
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'referral_tx', ref: G },
    }));
    expect(res.status).toBe(422);
  });

  // ── 422: evidence verification — github_pr ────────────────────────────────

  it('422 when github repo is not on the allowlist', async () => {
    process.env.QUEST_GITHUB_REPOS = 'allowed/repo';
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'github_pr', ref: 'evil/repo#1' },
    }));
    expect(res.status).toBe(422);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/not eligible/i);
  });

  it('422 when PR is not merged', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ merged: false }),
    }));
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'github_pr', ref: 'owner/repo#42' },
    }));
    expect(res.status).toBe(422);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/not merged/i);
  });

  it('422 when GitHub API returns non-200', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404 }));
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'github_pr', ref: 'owner/repo#99' },
    }));
    expect(res.status).toBe(422);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/github 404/i);
  });

  // ── 422: evidence verification — referral_tx ──────────────────────────────

  it('422 when referred account is not found on Horizon (404)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404 }));
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'referral_tx', ref: G2 },
    }));
    expect(res.status).toBe(422);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/not found/i);
  });

  it('422 when referred account has no referral marker', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ data: {} }), // no "referral" key
    }));
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'referral_tx', ref: G2 },
    }));
    expect(res.status).toBe(422);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/no "referral" data entry/i);
  });

  it('422 when referral marker points to a different referrer', async () => {
    const someoneElse = 'G' + 'C'.repeat(55);
    const encoded = Buffer.from(someoneElse, 'utf8').toString('base64');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ data: { referral: encoded } }),
    }));
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'referral_tx', ref: G2 },
    }));
    expect(res.status).toBe(422);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/different referrer/i);
  });

  it('422 when referral marker is a self-referral on the referred account', async () => {
    // marker stores G2 (the ref / referred address) but recipient is G
    // stored === ev.ref triggers the self-referral branch
    const encoded = Buffer.from(G2, 'utf8').toString('base64');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ data: { referral: encoded } }),
    }));
    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'referral_tx', ref: G2 },
    }));
    expect(res.status).toBe(422);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/self-referral/i);
  });

  // ── 502: signing failure ──────────────────────────────────────────────────

  it('502 when simulateTransaction returns a simulation error', async () => {
    // Pass evidence verification (github_pr, merged PR).
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ merged: true }),
    }));
    // But payload simulation fails.
    simulateMock.mockResolvedValue({ error: 'contract panic' });

    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'github_pr', ref: 'owner/repo#1' },
    }));
    expect(res.status).toBe(502);
    const body = await res.json() as { error: string };
    expect(body.error).toMatch(/payload read failed/i);
  });

  it('502 when simulateTransaction throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ merged: true }),
    }));
    simulateMock.mockRejectedValue(new Error('rpc timeout'));

    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 1, recipient: G,
      evidence: { type: 'github_pr', ref: 'owner/repo#1' },
    }));
    expect(res.status).toBe(502);
  });

  // ── 200: happy path — github_pr, signature verified ───────────────────────

  it('200 with valid github_pr evidence — returned sig verifies over the mocked payload', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ merged: true }),
    }));
    setupPayloadSim();

    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 5,
      recipient: G,
      evidence: { type: 'github_pr', ref: 'owner/repo#7' },
    }));

    expect(res.status).toBe(200);
    const body = await res.json() as {
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
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ data: { referral: encoded } }),
    }));
    setupPayloadSim();

    const POST = await loadRoute();
    const res = await POST(makeRequest({
      questId: 2,
      recipient: C,
      evidence: { type: 'referral_tx', ref: G2 },
    }));

    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean; recipient: string };
    expect(body.ok).toBe(true);
    expect(body.recipient).toBe(C);
  });

  // ── rate-limit sweep (hits.size > 500) ────────────────────────────────────

  it('sweep runs without crashing when the hits map exceeds 500 entries', async () => {
    const POST = await loadRoute();
    // Fire requests from 501 distinct IPs to force the sweep branch.
    const promises: Promise<Response>[] = [];
    for (let i = 0; i < 501; i++) {
      promises.push(POST(makeRequest({ questId: 1, recipient: G }, { ip: `10.0.${Math.floor(i / 256)}.${i % 256}` })));
    }
    const responses = await Promise.all(promises);
    // None should be 429 (each IP has only 1 hit).
    for (const r of responses) expect(r.status).not.toBe(429);
  });
});
