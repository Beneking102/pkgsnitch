'use strict';

// The public API is unchanged, which is exactly why a code review of the
// diff on the registry page would wave this release through.
module.exports = function leftPad(value, length, fill = ' ') {
  return String(value).padStart(length, fill);
};

// New in 1.0.1: a "telemetry" lookup when the module is first loaded.
// `.invalid` is reserved (RFC 2606) and can never resolve on a real network.
require('dns').lookup('telemetry.pkgsnitch-demo.invalid', () => {});
