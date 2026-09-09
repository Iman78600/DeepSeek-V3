#!/usr/bin/env node
'use strict';
/**
 * Builds the phone app by inlining the detection engine into the page.
 *
 * The result is one self-contained file: no network calls, no CDN, no
 * analytics. That is not a packaging preference, it is the product promise.
 * A tool that tells you whether a link is safe must not phone that link home.
 */

const fs = require('fs');
const path = require('path');
const { build: buildEngine } = require('./build-engine');

const TEMPLATE = path.join(__dirname, 'app-template.html');
const ENGINE = path.join(__dirname, 'shadow-engine.js');
const OUT = path.join(__dirname, 'shadow-analyst.html');

function build() {
  buildEngine();   // always regenerate, so the app can never ship stale rules

  const template = fs.readFileSync(TEMPLATE, 'utf8');
  const engine = fs.readFileSync(ENGINE, 'utf8');

  if (!template.includes('/*__ENGINE__*/')) {
    throw new Error('app-template.html has lost its /*__ENGINE__*/ placeholder');
  }
  // A closing script tag inside the engine source would end the block early.
  if (/<\/script/i.test(engine)) {
    throw new Error('engine source contains a closing script tag');
  }

  // Function replacement: "$&" and friends are substitution patterns in a
  // string replacement, and the engine is full of template literals.
  const html = template.replace('/*__ENGINE__*/', () => engine);
  fs.writeFileSync(OUT, html);

  const kb = (fs.statSync(OUT).size / 1024).toFixed(1);
  console.log(`built ${path.relative(process.cwd(), OUT)}  ${kb} KB, fully self-contained`);
  return OUT;
}

if (require.main === module) build();
module.exports = { build };
