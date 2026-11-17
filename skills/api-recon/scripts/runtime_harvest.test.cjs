const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const vm = require('node:vm');
const { sameOrigin, requestHeaders, injectAuthState, forwardRequest, cookieValue, main } = require('./runtime_harvest');

test('exact origins and credential recipients', () => {
  const origin = 'https://target.example';
  const cookies = [{ name: 'session', value: 'json:test-only' }];
  assert.equal(sameOrigin('https://TARGET.example:443/api/x', origin), true);
  for (const url of ['https://target.example.evil.invalid/api/', 'https://target.example:444/api/',
    'http://target.example/api/', 'https://target.example@evil.invalid/api/', 'https://user@target.example/api/', 'data:text/plain,x']) {
    assert.equal(sameOrigin(url, origin), false);
    assert.deepEqual(requestHeaders({ Cookie: 'old', Authorization: 'secret', 'Proxy-Authorization': 'proxy', Accept: 'ok' }, url, origin, cookies), { Accept: 'ok' });
  }
  assert.deepEqual(requestHeaders({ Cookie: 'old', Authorization: 'target-token' }, origin, origin, cookies),
    { Authorization: 'target-token', cookie: 'session=test-only' });
  assert.equal(cookieValue('b64json:{"id":1}'), Buffer.from('{"id":1}').toString('base64'));
});

test('DOM authentication exists only in the exact target document', () => {
  for (const origin of ['https://target.example', 'https://target.example:444', 'https://other.example']) {
    const sandbox = { location: { origin, pathname: '/' }, stored: {}, nativeCookie: '' };
    vm.createContext(sandbox);
    vm.runInContext(`class Document {};
      Object.defineProperty(Document.prototype, 'cookie', {
        get() { return nativeCookie; }, set(value) { nativeCookie = value; }
      });
      globalThis.document = new Document();
      globalThis.localStorage = {setItem(k,v) { stored[k] = v; }};`, sandbox);
    vm.runInContext(`(${injectAuthState.toString()})({token:'test-only'}, [{name:'session',value:'test-only'}], 'https://target.example')`, sandbox);
    if (origin === 'https://target.example') {
      assert.equal(sandbox.stored.token, 'test-only');
      assert.equal(vm.runInContext('document.cookie', sandbox), 'session=test-only');
      assert.equal(sandbox.nativeCookie, ''); // No domain cookie jar copy, including across ports.
    } else {
      assert.equal(sandbox.stored.token, undefined);
      assert.equal(vm.runInContext('document.cookie', sandbox), '');
    }
  }
});

test('configured cookies retain path boundaries and longest-path ordering', () => {
  const cookies = [{ name: 'session', value: 'root' }, { name: 'session', value: 'app1', path: '/app1' },
    { name: 'session', value: 'app2', path: '/app2' }];
  assert.equal(requestHeaders({}, 'https://target.example/app2/item', 'https://target.example', cookies).cookie,
    'session=app2; session=root');
  assert.equal(requestHeaders({}, 'https://target.example/app21', 'https://target.example', cookies).cookie,
    'session=root');
  const sandbox = { location: { origin: 'https://target.example', pathname: '/app2/item' }, nativeCookie: '' };
  vm.createContext(sandbox);
  vm.runInContext(`class Document {};
    Object.defineProperty(Document.prototype, 'cookie', { get() { return nativeCookie; }, set(v) { nativeCookie = v; } });
    globalThis.document = new Document();`, sandbox);
  vm.runInContext(`(${injectAuthState.toString()})(null, ${JSON.stringify(cookies)}, 'https://target.example')`, sandbox);
  assert.equal(vm.runInContext('document.cookie', sandbox), 'session=app2; session=root');
  sandbox.location.pathname = '/app1';
  assert.equal(vm.runInContext('document.cookie', sandbox), 'session=app1; session=root');
});

test('forwarding follows same-origin redirects and never contacts a foreign sink', async t => {
  const received = [];
  const other = http.createServer((req, res) => { received.push('LEAK'); res.end('foreign'); });
  await new Promise(resolve => other.listen(0, '127.0.0.1', resolve));
  t.after(() => other.close());
  const target = http.createServer((req, res) => {
    received.push({ url: req.url, method: req.method, cookie: req.headers.cookie });
    if (req.url.startsWith('/foreign/')) {
      res.writeHead(Number(req.url.split('/').pop()), { location: `http://127.0.0.1:${other.address().port}/api/sink` });
    } else if (req.url.startsWith('/local/')) {
      res.writeHead(Number(req.url.split('/').pop()), { location: '/done' });
    }
    res.end('ok');
  });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
  t.after(() => target.close());
  const origin = `http://127.0.0.1:${target.address().port}`;
  for (const status of [301, 302, 303, 307, 308]) {
    const options = { method: 'POST', body: 'data', headers: { cookie: 'test-only' } };
    const response = await forwardRequest(`${origin}/local/${status}`, options, origin);
    assert.equal(await response.text(), 'ok');
    assert.equal(received.at(-1).method, [307, 308].includes(status) ? 'POST' : 'GET');
    await assert.rejects(forwardRequest(`${origin}/foreign/${status}`, options, origin), /cross-origin/);
  }
  assert.equal(received.includes('LEAK'), false);
  assert.equal(received.every(r => r.cookie === 'test-only'), true);
});

test('redirects to userinfo, changed scheme, ports and loops fail closed', async () => {
  for (const destination of ['http://target.example/api', 'https://target.example:444/api', 'https://user@target.example/api']) {
    let calls = 0;
    const fake = async () => { calls++; return new Response('', { status: 302, headers: { location: destination } }); };
    await assert.rejects(forwardRequest('https://target.example/api', { method: 'GET', headers: {} }, 'https://target.example', fake));
    assert.equal(calls, 1);
  }
  await assert.rejects(forwardRequest('https://target.example/api', { method: 'GET', headers: {} }, 'https://target.example',
    async () => new Response('', { status: 302, headers: { location: '/loop' } })), /too many redirects/);
});

test('HTTPS rejects an untrusted server before sending credentials and accepts a private CA', async t => {
  const openssl = process.env.ARTEX_TEST_OPENSSL || 'openssl';
  try { execFileSync(openssl, ['version'], { stdio: 'ignore' }); }
  catch { return t.skip('openssl required for ephemeral TLS fixture'); }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'recon-tls-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cert = path.join(dir, 'cert.pem'), key = path.join(dir, 'key.pem'), config = path.join(dir, 'openssl.cnf');
  fs.writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', config,
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const received = [];
  const server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
    received.push(req.headers.cookie);
    res.end('trusted');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const origin = `https://127.0.0.1:${server.address().port}`;
  await assert.rejects(forwardRequest(origin, { method: 'GET', headers: { cookie: 'test-only' } }, origin));
  assert.deepEqual(received, []);
  const child = `const {forwardRequest}=require(process.argv[1]);
    forwardRequest(process.argv[2], {method:'GET',headers:{cookie:'test-only'}}, process.argv[2])
      .then(r=>r.text()).then(t=>process.stdout.write(t)).catch(e=>{console.error(e.message);process.exitCode=1;});`;
  const { stdout } = await promisify(execFile)(process.execPath, ['-e', child, path.join(__dirname, 'runtime_harvest.js'), origin],
    { env: { ...process.env, NODE_EXTRA_CA_CERTS: cert, NODE_TLS_REJECT_UNAUTHORIZED: '1' }, timeout: 10000 });
  assert.equal(stdout, 'trusted');
  assert.deepEqual(received, ['test-only']);
});

test('Chromium keeps configured authentication out of foreign frames, redirects and popups',
  { skip: !process.env.CHROMIUM, timeout: 30000 }, async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'recon-browser-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const foreignRequests = [], observations = [];
  let targetOrigin;
  const foreign = http.createServer((req, res) => {
    foreignRequests.push({ url: req.url, headers: req.headers });
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'text/html');
    res.end(`<script>
      fetch('/observed?cookie='+encodeURIComponent(document.cookie)+'&storage='+encodeURIComponent(localStorage.getItem('token')||''));
      fetch('${targetOrigin}/profile', {credentials:'omit'}).then(r=>r.text())
        .then(data=>fetch('/profile-result?data='+encodeURIComponent(data)));
    </script>`);
  });
  await new Promise(resolve => foreign.listen(0, '127.0.0.1', resolve));
  t.after(() => foreign.close());
  const foreignOrigin = `http://127.0.0.1:${foreign.address().port}`;
  const target = http.createServer((req, res) => {
    if (req.url === '/profile') {
      observations.push({ url: req.url, headers: req.headers });
      res.setHeader('Access-Control-Allow-Origin', '*');
      return res.end(req.headers.cookie ? 'authenticated' : 'anonymous');
    }
    if (req.url.startsWith('/observed')) observations.push({ url: req.url, headers: req.headers });
    if (req.url === '/redirect') {
      res.writeHead(302, { location: foreignOrigin + '/redirected' });
      return res.end();
    }
    if (req.url === '/api/probe') {
      observations.push({ url: req.url, headers: req.headers });
      return res.end('{"code":0}');
    }
    res.setHeader('Content-Type', 'text/html');
    if (req.url === '/') {
      res.end(`<iframe src="/frame"></iframe><iframe src="${foreignOrigin}/frame"></iframe>
        <script>
          fetch('/observed?kind=main&cookie='+encodeURIComponent(document.cookie)+'&storage='+localStorage.getItem('token'));
          fetch('/api/probe'); fetch('/redirect');
          window.open('${foreignOrigin}/popup');
        </script>`);
    } else if (req.url === '/frame') {
      res.end(`<script>fetch('/observed?kind=frame&cookie='+encodeURIComponent(document.cookie)+'&storage='+localStorage.getItem('token'))</script>`);
    } else res.end('ok');
  });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
  t.after(() => target.close());
  targetOrigin = `http://127.0.0.1:${target.address().port}`;
  const config = path.join(dir, 'config.json');
  fs.writeFileSync(config, JSON.stringify({ baseUrl: `http://127.0.0.1:${target.address().port}/`,
    chromium: process.env.CHROMIUM, cookies: [{ name: 'session', value: 'test-only' }],
    localStorage: { token: 'test-only' }, routes: [], recordWs: false, waitMs: 1200 }));
  await main(config);
  for (const kind of ['main', 'frame']) {
    const observation = observations.find(r => r.url.startsWith('/observed?kind=' + kind));
    assert.ok(observation, `missing ${kind} observation`);
    const params = new URL(observation.url, 'http://fixture').searchParams;
    assert.equal(params.get('cookie'), 'session=test-only');
    assert.equal(params.get('storage'), 'test-only');
  }
  assert.equal(observations.find(r => r.url === '/api/probe')?.headers.cookie, 'session=test-only');
  const foreignProbes = observations.filter(r => r.url === '/profile');
  assert.ok(foreignProbes.length >= 2, 'foreign frame and popup must exercise the target');
  assert.ok(foreignProbes.every(r => !r.headers.cookie), 'foreign documents must not gain target credentials');
  assert.ok(foreignRequests.some(r => r.url === '/profile-result?data=anonymous'));
  assert.ok(!foreignRequests.some(r => r.url === '/profile-result?data=authenticated'));
  for (const route of ['/frame', '/popup', '/redirected']) {
    assert.ok(foreignRequests.some(r => r.url === route), `missing foreign ${route}`);
  }
  const foreignDocuments = foreignRequests.filter(r => r.url.startsWith('/observed?'));
  assert.ok(foreignDocuments.length >= 2);
  for (const req of foreignRequests) {
    assert.equal(req.headers.cookie, undefined, req.url);
    assert.equal(req.headers.authorization, undefined, req.url);
    if (req.url.startsWith('/observed?')) {
      const params = new URL(req.url, foreignOrigin).searchParams;
      assert.equal(params.get('cookie'), '');
      assert.equal(params.get('storage'), '');
    }
  }
});

test('Chromium refuses an untrusted HTTPS document before sending configured cookies',
  { skip: !process.env.CHROMIUM, timeout: 30000 }, async t => {
  const openssl = process.env.ARTEX_TEST_OPENSSL || 'openssl';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'recon-browser-tls-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cert = path.join(dir, 'cert.pem'), key = path.join(dir, 'key.pem'), config = path.join(dir, 'openssl.cnf');
  fs.writeFileSync(config, '[req]\ndistinguished_name=dn\n[dn]\n');
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', config,
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const received = [];
  const server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
    received.push(req.headers.cookie);
    res.end('untrusted');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const cfg = path.join(dir, 'config.json');
  fs.writeFileSync(cfg, JSON.stringify({ baseUrl: `https://127.0.0.1:${server.address().port}/`,
    chromium: process.env.CHROMIUM, cookies: [{ name: 'session', value: 'test-only' }],
    routes: [], recordWs: false, waitMs: 1 }));
  await main(cfg);
  assert.deepEqual(received, []);
  assert.match(JSON.parse(fs.readFileSync(path.join(dir, 'runtime_api.json'), 'utf8')).shell.url, /^chrome-error:/);
});
