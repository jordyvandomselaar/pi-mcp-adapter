import http from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AuthSessionExpiredError,
  AuthSessionSupersededError,
  LoopbackAuthSessionManager,
  MemoryInteractiveAuthSessionStore,
} from "../auth-session-manager.js";

async function request(url: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname + parsed.search,
        method: "GET",
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf-8"),
          });
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("LoopbackAuthSessionManager", () => {
  const managers: LoopbackAuthSessionManager[] = [];

  afterEach(async () => {
    await Promise.all(managers.splice(0).map((manager) => manager.close()));
  });

  it("handles first-time callback completion with PKCE/browser coordination", async () => {
    const browserOpener = vi.fn();
    const manager = new LoopbackAuthSessionManager({ browserOpener });
    managers.push(manager);

    const session = await manager.startAttempt("fingerprint-a");
    expect(session.redirectUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);
    await session.saveCodeVerifier("pkce-verifier");
    await expect(session.getCodeVerifier()).resolves.toBe("pkce-verifier");

    await session.openAuthorization("https://auth.example.test/authorize?client_id=pi");
    expect(browserOpener).toHaveBeenCalledTimes(1);
    expect(browserOpener.mock.calls[0][0].toString()).toBe("https://auth.example.test/authorize?client_id=pi");

    const callbackPromise = session.waitForCallback();
    const response = await request(`${session.redirectUrl}?code=auth-code-123&state=${session.state}`);
    const callback = await callbackPromise;

    expect(response.status).toBe(200);
    expect(response.body).toContain("Authorization complete");
    expect(callback).toMatchObject({
      sessionId: session.sessionId,
      fingerprint: "fingerprint-a",
      state: session.state,
      authorizationCode: "auth-code-123",
    });
  });

  it("accepts state exactly once and rejects replayed callbacks", async () => {
    const manager = new LoopbackAuthSessionManager();
    managers.push(manager);

    const session = await manager.startAttempt("fingerprint-b");
    const callbackPromise = session.waitForCallback();

    const firstResponse = await request(`${session.redirectUrl}?code=first-code&state=${session.state}`);
    await expect(callbackPromise).resolves.toMatchObject({ authorizationCode: "first-code" });

    const replayResponse = await request(`${session.redirectUrl}?code=second-code&state=${session.state}`);

    expect(firstResponse.status).toBe(200);
    expect(replayResponse.status).toBe(409);
    expect(replayResponse.body).toContain("already been used");
  });

  it("expires pending sessions, cleans them up, and rejects late callbacks", async () => {
    const store = new MemoryInteractiveAuthSessionStore();
    const manager = new LoopbackAuthSessionManager({
      store,
      sessionTtlMs: 25,
      replayRetentionMs: 50,
    });
    managers.push(manager);

    const session = await manager.startAttempt("fingerprint-c");
    const callbackPromise = session.waitForCallback();

    await new Promise((resolve) => setTimeout(resolve, 60));

    await expect(callbackPromise).rejects.toBeInstanceOf(AuthSessionExpiredError);
    expect(await store.list()).toEqual([]);

    const lateResponse = await request(`${session.redirectUrl}?code=too-late&state=${session.state}`);
    expect(lateResponse.status).toBe(410);
    expect(lateResponse.body).toContain("expired");
  });

  it("supersedes older concurrent attempts for the same fingerprint", async () => {
    const manager = new LoopbackAuthSessionManager();
    managers.push(manager);

    const first = await manager.startAttempt("shared-fingerprint");
    const firstWait = first.waitForCallback();

    const second = await manager.startAttempt("shared-fingerprint");
    const secondWait = second.waitForCallback();

    await expect(firstWait).rejects.toBeInstanceOf(AuthSessionSupersededError);

    const staleResponse = await request(`${first.redirectUrl}?code=stale&state=${first.state}`);
    expect(staleResponse.status).toBe(409);
    expect(staleResponse.body).toContain("newer authorization session replaced this one");

    const freshResponse = await request(`${second.redirectUrl}?code=fresh&state=${second.state}`);
    const callback = await secondWait;

    expect(freshResponse.status).toBe(200);
    expect(callback.authorizationCode).toBe("fresh");
    expect(callback.state).toBe(second.state);
  });
});
