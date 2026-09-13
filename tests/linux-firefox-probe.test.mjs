import test from 'node:test';
import assert from 'node:assert/strict';
import { runInNewContext } from 'node:vm';
import { existsSync } from 'node:fs';
import { FIREFOX_RUNNER_URL, fixtureUrl, MARKER, QUEUE, requireNativeSession, selectQueueScript, submitScript, sessionEnvironment } from '../scripts/linux-firefox-probe.mjs';

test('native probe resolves its own browser driver without starting it', () => {
  assert.equal(FIREFOX_RUNNER_URL.href, new URL('../scripts/firefox-probe-driver.mjs', import.meta.url).href);
  assert.ok(existsSync(FIREFOX_RUNNER_URL));
});

test('browser receives desktop session variables, never arbitrary shell credentials', () => {
  const env = sessionEnvironment({WAYLAND_DISPLAY:'wayland-0', LANG:'en_US.UTF-8', PATH:'/usr/bin',
    FIN3000_QA_TOTP_SECRET:'sentinel', AWS_SECRET_ACCESS_KEY:'sentinel', LD_PRELOAD:'/unsafe',
    FIN3000_FIREFOX_RUNNER:'/unsafe', NODE_OPTIONS:'--import /unsafe'});
  assert.deepEqual(env, {PATH:'/usr/bin', LANG:'en_US.UTF-8', WAYLAND_DISPLAY:'wayland-0', MOZ_ENABLE_WAYLAND:'1'});
  assert.ok(!JSON.stringify(env).includes('sentinel'));
});

test('fixture is entirely inline and contains only synthetic content', () => {
  const html = decodeURIComponent(fixtureUrl.split(',').slice(1).join(','));
  assert.match(fixtureUrl, /^data:text\/html/);
  assert.ok(html.includes(MARKER));
  assert.doesNotMatch(html, /https?:|<script|<img|<iframe/);
});

test('headless, X11 and non-Snap results cannot pass native session validation', () => {
  requireNativeSession({windowProtocol: 'wayland', executable: '/snap/firefox/8863/usr/lib/firefox/firefox'});
  for (const session of [
    {windowProtocol: 'x11', executable: '/snap/firefox/current/firefox'},
    {windowProtocol: 'headless', executable: '/snap/firefox/current/firefox'},
    {windowProtocol: 'wayland', executable: '/usr/lib/firefox/firefox'},
  ]) assert.throws(() => requireNativeSession(session));
});

test('submission checks the selected destination and active settings before clicking', () => {
  assert.ok(selectQueueScript().includes(QUEUE));
  assert.match(submitScript(), /Refusing to print to any other destination/);
  assert.match(submitScript(), /settings\?\.printerName/);
  assert.match(submitScript(), /button\.disabled/);
  assert.match(submitScript(), /button\.click\(\)/);
});

test('destination picker emits the input event used by Firefox PrintSettingSelect', () => {
  const events = [];
  const picker = {options:[{value:QUEUE}], value:'Other', dispatchEvent:event=>events.push(event.type)};
  const doc = {querySelector:()=>picker, defaultView:{Event:class {constructor(type){this.type=type;}}}};
  const context = {gBrowser:{selectedBrowser:{}}, PrintUtils:{getTabDialogBox:()=>({
    getTabDialogManager:()=>({dialogs:[{_frame:{contentDocument:doc}}]})})}};
  assert.equal(runInNewContext('(()=>{' + selectQueueScript() + '})()', context), true);
  assert.equal(picker.value, QUEUE);
  assert.deepEqual(events, ['input']);
});
