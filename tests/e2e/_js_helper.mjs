// JS end of the cross-SDK e2e suite. Invoked by tests/e2e/conftest.py's
// js_helper fixture; loads the BUILT sdk from $SP_E2E_JS_DIST and prints one
// JSON result line on stdout. All modes use the account-default key (bare
// password), so no topic setup is needed.
//
// Modes:
//   send-encrypted-chain <pw> <parentSecret> <childSecret>
//   read-decrypt         <pw> <taskId> <secret>
//   send-parity          <pw> <secret>

const [mode, ...rest] = process.argv.slice(2);
const sdk = await import(process.env.SP_E2E_JS_DIST);
const { Client, decrypt } = sdk;

const BASE = process.env.SP_E2E_BASE_URL;
const TOKEN = process.env.SP_E2E_API_TOKEN;

const out = (o) => {
  console.log(JSON.stringify(o));
  process.exit(0);
};

const client = (pw) => new Client({ apiToken: TOKEN, baseUrl: BASE, passwords: pw });

const senderRead = async (taskId) => {
  const res = await fetch(`${BASE}/v1/tasks/${taskId}`, { headers: { "API-Token": TOKEN } });
  return { ok: res.ok, body: res.ok ? await res.json() : await res.text() };
};

if (mode === "send-encrypted-chain") {
  const [pw, s1, s2] = rest;
  const c = client(pw);
  const task = await c.sendTask({ content: `parent ${s1}` });
  const res = await c.appendSubtask({ appendToken: task.appendToken, content: `child ${s2}` });
  const sub = (JSON.stringify(res).match(/sub_[A-Za-z0-9-]+/) ?? [null])[0];
  c.close();
  out({ taskId: task.taskId, subtaskId: sub });
}

if (mode === "read-decrypt") {
  const [pw, taskId, secret] = rest;
  const c = client(pw);
  const read = await senderRead(taskId);
  let ciphertext = false;
  let decrypted = false;
  if (read.ok) {
    ciphertext = !JSON.stringify(read.body).includes(secret);
    const keyring = await c.keyring({ includePasswordSalt: true });
    const key = read.body.encryption ? keyring.keyForMarker(read.body.encryption) : undefined;
    if (key) {
      try {
        decrypted = (await decrypt(key, read.body.content)).includes(secret);
      } catch {
        decrypted = false;
      }
    }
  }
  c.close();
  out({ found: read.ok, ciphertext, decrypted });
}

if (mode === "send-parity") {
  const [pw, s] = rest;
  const c = client(pw);
  const task = await c.sendTask({
    content: `c ${s}`,
    title: "parity",
    tag: "parity-tag",
  });
  c.close();
  out({ taskId: task.taskId });
}

console.error(`unknown mode: ${mode}`);
process.exit(2);
