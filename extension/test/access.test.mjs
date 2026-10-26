import { test } from "node:test";
import assert from "node:assert/strict";

// If Chrome refuses to close storage.local to trusted contexts, the worker fails closed: it reads, writes and
// registers nothing, so a content script never runs beside open pairing keys. (A real content-script check is the
// manual one in docs/DESIGN.md, "Content scripts can't read the pairing".)
const touched = [];
globalThis.chrome = {
  runtime: {
    id: "sphinxcodes", getURL: (p) => `chrome-extension://sphinxcodes/${p}`, getManifest: () => ({ host_permissions: [] }),
    onMessage: { addListener() {} }, onStartup: { addListener() {} }, onInstalled: { addListener() {} },
  },
  storage: { local: {
    setAccessLevel: async () => { throw new Error("not supported"); },
    get: async () => { touched.push("get"); return {}; }, set: async () => { touched.push("set"); }, remove: async () => { touched.push("remove"); },
  } },
  permissions: { getAll: async () => ({ origins: ["https://github.com/*"] }), remove: async () => true, onRemoved: { addListener() {} } },
  scripting: { registerContentScripts: async () => { touched.push("register"); }, unregisterContentScripts: async () => {} },
};
globalThis.fetch = async () => ({ text: async () => "" });
const { _test } = await import("../background.js");

test("a refused access level means no storage and no content script", async () => {
  await assert.rejects(_test.register());
  await assert.rejects(_test.options({ t: "status" }));
  await assert.rejects(_test.send("domains.request", {}));
  assert.deepEqual(touched, []);
});
