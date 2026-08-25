#!/usr/bin/env node
// Replace the proto symlink with a real file copy so `npm pack` includes it.
// `postpack.js` restores the symlink.
const fs = require('fs');
const path = require('path');

const link = path.join(__dirname, '..', 'proto', 'vault.proto');
const stat = fs.lstatSync(link);
if (!stat.isSymbolicLink()) {
  console.log('[prepack] proto/vault.proto is already a regular file, skipping');
  process.exit(0);
}

const target = fs.readlinkSync(link);
fs.writeFileSync(
  path.join(__dirname, 'prepack.linktarget'),
  target,
  'utf8',
);

const content = fs.readFileSync(link);
fs.unlinkSync(link);
fs.writeFileSync(link, content);
console.log(`[prepack] materialized proto/vault.proto from ${target}`);
