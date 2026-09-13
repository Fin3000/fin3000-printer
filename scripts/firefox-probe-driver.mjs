/** Synthetic printer WebDriver transport. Adapted from Fin3000's Apache-2.0
 * browser-timetracker methods, without extension, account or profile access. */
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export class FirefoxProbeDriver {
  constructor(port) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid_driver_port');
    this.base = `http://127.0.0.1:${port}`;
    this.sid = null;
  }
  async raw(method, route, data) {
    const response = await fetch(this.base + route, {
      method, redirect: 'error', signal: AbortSignal.timeout(45_000),
      ...(data === undefined ? {} : {
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
      }),
    });
    const body = await response.json();
    if (!response.ok) {
      const error = new Error(body.value?.error || 'webdriver_http_error');
      error.webdriverMessage = body.value?.message;
      throw error;
    }
    return body.value;
  }
  async call(method, route, data) {
    if (!this.sid) throw new Error('webdriver_session_missing');
    return this.raw(method, `/session/${encodeURIComponent(this.sid)}${route}`, data);
  }
  async start() {
    const session = await this.raw('POST', '/session', {
      capabilities: { alwaysMatch: {
        browserName: 'firefox', 'moz:firefoxOptions': {
          args: [], prefs: { 'browser.shell.checkDefaultBrowser': false, 'intl.locale.requested': 'de' },
        },
      } },
    });
    if (typeof session?.sessionId !== 'string' || !session.sessionId) throw new Error('invalid_driver_session');
    this.sid = session.sessionId;
    this.version = session.capabilities?.browserVersion;
    await this.call('POST', '/window/rect', { width: 1280, height: 1000 });
    await this.call('POST', '/timeouts', { implicit: 0, pageLoad: 30_000, script: 15_000 });
  }
  chrome() { return this.call('POST', '/moz/context', { context: 'chrome' }); }
  script(script, args = []) { return this.call('POST', '/execute/sync', { script, args }); }
  async wait(check, timeout = 20_000, { signal, fatal } = {}) {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      signal?.throwIfAborted();
      const error = fatal?.();
      if (error) throw error;
      try { const value = await check(); if (value) return value; }
      catch { /* Retry transient missing/stale native dialogs within the bound. */ }
      await pause(200);
    }
    throw new Error('qa_state_timeout');
  }
  async close() {
    try { if (this.sid) await this.call('DELETE', ''); }
    catch { /* Driver may already be stopped; still forget the local session. */ }
    finally { this.sid = null; }
  }
}
