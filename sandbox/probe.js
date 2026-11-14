'use strict';
// The sinkhole. Runs as root inside the sandbox once the real network has
// been disconnected. It answers every DNS query with 127.0.0.1 and accepts
// TCP on the usual web ports, so that code which "phones home" reveals the
// host name, the TLS server name or the HTTP request line it wanted to send.
// Nothing ever leaves the container.

const dgram = require('dgram');
const net = require('net');
const fs = require('fs');

const out = fs.openSync('/probe/net.jsonl', 'a');
const log = (event) => fs.writeSync(out, JSON.stringify({ ts: Date.now(), ...event }) + '\n');

// --- DNS ------------------------------------------------------------------

function parseQuestion(msg) {
  const labels = [];
  let off = 12;
  for (;;) {
    const len = msg[off];
    if (len === undefined || len > 63) throw new Error('bad name');
    if (len === 0) break;
    labels.push(msg.toString('latin1', off + 1, off + 1 + len));
    off += len + 1;
  }
  return { name: labels.join('.').toLowerCase(), qtype: msg.readUInt16BE(off + 1), end: off + 5 };
}

function answer(msg) {
  const q = parseQuestion(msg);
  const header = Buffer.alloc(12);
  msg.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180, 2); // response, recursion available, no error
  header.writeUInt16BE(1, 4);
  let record = Buffer.alloc(0);
  if (q.qtype === 1) {
    // A record -> 127.0.0.1. Other types get an empty answer.
    record = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 127, 0, 0, 1]);
    header.writeUInt16BE(1, 6);
  }
  return { q, packet: Buffer.concat([header, msg.subarray(12, q.end), record]) };
}

function dnsServer(type, address) {
  const sock = dgram.createSocket(type);
  sock.on('error', () => sock.close());
  sock.on('message', (msg, peer) => {
    try {
      const { q, packet } = answer(msg);
      if (q.name && q.name !== 'localhost') log({ t: 'dns', name: q.name, qtype: q.qtype });
      sock.send(packet, peer.port, peer.address);
    } catch {
      /* malformed query: ignore */
    }
  });
  sock.bind(53, address);
}

// How much of an unencrypted request is kept, to spot planted secrets in it.
const SAMPLE = 2048;

// --- TCP sink ---------------------------------------------------------------

function serverName(hello) {
  // TLS record header (5) + handshake header (4) + version (2) + random (32)
  let off = 43;
  off += 1 + hello[off]; // session id
  off += 2 + hello.readUInt16BE(off); // cipher suites
  off += 1 + hello[off]; // compression methods
  const end = off + 2 + hello.readUInt16BE(off);
  off += 2;
  while (off + 4 <= end) {
    const type = hello.readUInt16BE(off);
    const len = hello.readUInt16BE(off + 2);
    if (type === 0) {
      const nameLen = hello.readUInt16BE(off + 7);
      return hello.toString('latin1', off + 9, off + 9 + nameLen);
    }
    off += 4 + len;
  }
  return null;
}

function classify(data, port) {
  if (data[0] === 0x16 && data[5] === 0x01) {
    let sni = null;
    try {
      sni = serverName(data);
    } catch {
      /* truncated hello */
    }
    return { t: 'tls', port, sni };
  }
  const text = data.toString('latin1');
  const request = /^([A-Z]{3,8}) (\S+) HTTP\/1\.[01]\r?\n/.exec(text);
  if (request) {
    const host = /\r?\nhost:[ \t]*([^\r\n]+)/i.exec(text);
    return { t: 'http', port, method: request[1], path: request[2].slice(0, 200), host: host ? host[1].trim() : null, data: text.slice(0, SAMPLE) };
  }
  return { t: 'tcp', port, bytes: data.length, data: text.slice(0, SAMPLE) };
}

function sink(port) {
  const server = net.createServer((sock) => {
    sock.setTimeout(3000, () => sock.destroy());
    sock.on('error', () => {});
    sock.once('data', (data) => {
      log(classify(data, port));
      sock.destroy();
    });
  });
  server.on('error', () => {});
  server.listen(port, '0.0.0.0');
}

dnsServer('udp4', '0.0.0.0');
dnsServer('udp6', '::1');
[80, 443].forEach(sink);
setTimeout(() => fs.writeFileSync('/probe/ready', ''), 150);
