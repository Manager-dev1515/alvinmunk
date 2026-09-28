/**
 * Tests for issue #208: leaderboard handle lookups were cancelled by every 5-second
 * poll because the handle-lookup effect depended on the `rows` array reference rather
 * than the stable set of addresses, and `setRows` was called unconditionally on every
 * tick even when nothing changed.
 *
 * Acceptance criteria (from the issue):
 *  - With reverseHandle mocked to take 8 s, handles still appear.
 *  - Each address is looked up at most once while a lookup is pending.
 *  - A vitest with fake timers covers the poll/lookup interaction.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act, waitFor } from '@testing-library/react';
import React from 'react';

// ── hoisted mocks (must come before any import that pulls the real modules) ──

const { fetchLeaderboardMock, reverseHandleMock, loadProfileMock } = vi.hoisted(() => ({
  fetchLeaderboardMock: vi.fn(),
  reverseHandleMock: vi.fn(),
  loadProfileMock: vi.fn(),
}));

vi.mock('@/lib/leaderboard', () => ({ fetchLeaderboard: fetchLeaderboardMock }));
vi.mock('@/lib/registry', () => ({ reverseHandle: reverseHandleMock }));
vi.mock('@/lib/profile', () => ({ loadProfile: loadProfileMock }));

// Stub out every UI component the page imports so the test stays fast and
// import-light; we only care about the data/effect logic.
vi.mock('@/components/brand/crest', () => ({ Crest: () => null }));
vi.mock('@/components/fx/frame', () => ({
  Frame: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock('@/components/fx/share-row', () => ({ ShareRow: () => null }));
vi.mock('@/components/ui/skeleton', () => ({ Skeleton: () => null }));
vi.mock('@/components/ui/state-art', () => ({ StateArt: () => null }));
vi.mock('@/components/ui/sticker', () => ({ Sticker: () => null }));
vi.mock('@/lib/i18n', () => ({
  useTranslations: () => (key: string) => key,
}));
vi.mock('@/lib/utils', () => ({
  cn: (...c: string[]) => c.filter(Boolean).join(' '),
  shortAddress: (a: string) => a.slice(0, 6) + '…' + a.slice(-4),
}));

import LeaderboardPage from './page';

// ── helpers ──

const ADDR_A = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ADDR_B = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

function makeRows(addresses: string[]) {
  return addresses.map((address, i) => ({
    rank: i + 1,
    address,
    score: 100 - i * 10,
    flagged: false,
  }));
}

// ── tests ──

describe('LeaderboardPage — poll / handle-lookup interaction (issue #208)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    loadProfileMock.mockReturnValue(null);
    // Default: instant empty response, so the loading skeleton disappears quickly.
    fetchLeaderboardMock.mockResolvedValue([]);
    reverseHandleMock.mockResolvedValue(null);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('shows @handle for an address even when reverseHandle takes 8 s', async () => {
    // reverseHandle resolves after 8 s (longer than the 5-s poll interval).
    reverseHandleMock.mockImplementation(
      (addr: string) =>
        new Promise((resolve) =>
          setTimeout(() => resolve(addr === ADDR_A ? 'alice' : null), 8_000),
        ),
    );

    fetchLeaderboardMock.mockResolvedValue(makeRows([ADDR_A]));

    render(<LeaderboardPage />);

    // Let the first poll settle and the handle lookup start.
    await act(async () => {
      await vi.runAllTicks(); // flush microtasks (fetchLeaderboard resolves)
    });

    // Advance 5 s — the second poll fires. Handles should NOT be reset to
    // the short address because the lookup is still in flight.
    await act(async () => {
      vi.advanceTimersByTime(5_000);
      await vi.runAllTicks();
    });

    // Still loading handles — the short address should be visible (not a crash).
    expect(screen.queryByText('@alice')).toBeNull();

    // Advance 3 more seconds — total 8 s — the reverseHandle promise resolves.
    await act(async () => {
      vi.advanceTimersByTime(3_000);
      await vi.runAllTicks();
    });

    // The handle should now appear.
    await waitFor(() => expect(screen.getByText('@alice')).toBeTruthy());
  });

  it('looks up each address at most once while a lookup is pending', async () => {
    // Slow lookup — takes longer than two poll intervals.
    reverseHandleMock.mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(null), 12_000)),
    );

    fetchLeaderboardMock.mockResolvedValue(makeRows([ADDR_A, ADDR_B]));

    render(<LeaderboardPage />);

    // First poll.
    await act(async () => { await vi.runAllTicks(); });

    // Two more polls fire (each at +5 s and +10 s).
    await act(async () => {
      vi.advanceTimersByTime(10_000);
      await vi.runAllTicks();
    });

    // Despite 3 polls, reverseHandle should have been called exactly once per
    // address (2 total) — not 6 times (3 polls × 2 addresses).
    expect(reverseHandleMock).toHaveBeenCalledTimes(2);
    expect(reverseHandleMock).toHaveBeenCalledWith(ADDR_A);
    expect(reverseHandleMock).toHaveBeenCalledWith(ADDR_B);
  });

  it('does not restart lookups when the poll returns identical data', async () => {
    const rows = makeRows([ADDR_A]);
    // Return a *new array* on every tick, but with identical content.
    fetchLeaderboardMock.mockImplementation(async () => [...rows]);

    reverseHandleMock.mockResolvedValue('alice');

    render(<LeaderboardPage />);

    await act(async () => { await vi.runAllTicks(); });

    // Three more polls — same content each time.
    await act(async () => {
      vi.advanceTimersByTime(15_000);
      await vi.runAllTicks();
    });

    // The address-key is stable, so the lookup effect didn't re-run.
    // reverseHandle should have been called exactly once.
    expect(reverseHandleMock).toHaveBeenCalledTimes(1);
  });

  it('still resolves handles for new addresses that appear after the initial poll', async () => {
    // First poll: only ADDR_A.
    fetchLeaderboardMock.mockResolvedValueOnce(makeRows([ADDR_A]));
    // Second poll: both ADDR_A and ADDR_B.
    fetchLeaderboardMock.mockResolvedValue(makeRows([ADDR_A, ADDR_B]));

    reverseHandleMock.mockImplementation((addr: string) =>
      Promise.resolve(addr === ADDR_A ? 'alice' : 'bob'),
    );

    render(<LeaderboardPage />);

    // First poll settles.
    await act(async () => { await vi.runAllTicks(); });

    // ADDR_A resolved immediately; ADDR_B is not yet in the list.
    await waitFor(() => expect(reverseHandleMock).toHaveBeenCalledWith(ADDR_A));
    expect(reverseHandleMock).not.toHaveBeenCalledWith(ADDR_B);

    // Second poll fires at +5 s, brings in ADDR_B.
    await act(async () => {
      vi.advanceTimersByTime(5_000);
      await vi.runAllTicks();
    });

    await waitFor(() => expect(reverseHandleMock).toHaveBeenCalledWith(ADDR_B));
    await waitFor(() => expect(screen.getByText('@bob')).toBeTruthy());
  });
});
