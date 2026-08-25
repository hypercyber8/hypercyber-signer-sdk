#!/usr/bin/env node
// Restore the proto symlink that `prepack.js` materialized.
const fs = require('fs');
const path = require('path');

const link = path.join(__dirname, '..', 'proto', 'vault.proto');
const stash = path.join(__dirname, 'prepack.linktarget');

if (!fs.existsSync(stash)) {
  console.log('[postpack] no stashed link target, skipping');
  process.exit(0);
}

const target = fs.readFileSync(stash, 'utf8');
fs.unlinkSync(link);
fs.symlinkSync(target, link);
fs.unlinkSync(stash);
console.log(`[postpack] restored proto/vault.proto -> ${target}`);
