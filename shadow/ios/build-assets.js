#!/usr/bin/env node
'use strict';
/**
 * Copies the shared JavaScript into the iOS app bundle.
 *
 * The iOS app does not reimplement any detection logic. It carries the same
 * three files the desktop and the phone web app use, so a rule added once
 * applies everywhere. Run this before building in Xcode.
 */

const fs = require('fs');
const path = require('path');

const { build: buildEngine } = require('../mobile/build-engine');
const { build: buildBlocker } = require('../mobile/build-content-blocker');
const { shieldSource } = require('../src/main/hardening/fingerprint-shield');

const RESOURCES = path.join(__dirname, 'Shadow', 'Resources');

function build() {
  fs.mkdirSync(RESOURCES, { recursive: true });

  // 1. The detection engine.
  const enginePath = buildEngine();
  fs.copyFileSync(enginePath, path.join(RESOURCES, 'shadow-engine.js'));

  // 2. The blocklists, as a WebKit content rule list.
  const blockerPath = buildBlocker();
  fs.copyFileSync(blockerPath, path.join(RESOURCES, 'shadow-blocker.json'));

  // 3. The fingerprint shield, with placeholders FingerprintShield.swift
  //    substitutes at launch. The seed has to be per-launch, so it cannot be
  //    baked in here.
  const template = shieldSource(
    { canvasNoise: true, fontProtection: true, timingJitter: true, blockWebgl: false },
    0,
  )
    .replace(/const SEED = \d+;/, 'const SEED = __SHADOW_SEED__;')
    .replace(/const CFG = \{[^\n]*\};/, 'const CFG = __SHADOW_CONFIG__;');

  if (!template.includes('__SHADOW_SEED__') || !template.includes('__SHADOW_CONFIG__')) {
    throw new Error('shield placeholders were not substituted; fingerprint-shield.js has changed shape');
  }
  fs.writeFileSync(path.join(RESOURCES, 'fingerprint-shield.js'), template);

  console.log('\niOS resources written to ios/Shadow/Resources/:');
  for (const f of fs.readdirSync(RESOURCES)) {
    const kb = (fs.statSync(path.join(RESOURCES, f)).size / 1024).toFixed(1);
    console.log(`  ${f.padEnd(24)} ${kb} KB`);
  }
  console.log('\nAdd that folder to the Xcode target as a folder reference, not a group,');
  console.log('so the files stay in sync when you regenerate them.');
}

if (require.main === module) build();
module.exports = { build };
