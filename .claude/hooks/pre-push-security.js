#!/usr/bin/env node
/**
 * Pre-push security hook for Aegis
 * Scans staged/committed files for leaked secrets before any git push.
 *
 * Install: Add to .claude/settings.json hooks or copy to .git/hooks/pre-push
 */

const { execSync } = require('child_process');
const path = require('path');

const SECRET_PATTERNS = [
  { name: 'GitHub PAT', pattern: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'npm token', pattern: /npm_[a-zA-Z0-9]{30,}/g },
  { name: 'Synthesis API key', pattern: /sk-synth-[a-f0-9]{40,}/g },
  { name: 'Private key (hex)', pattern: /(?:private.?key|PRIVATE.?KEY)\s*[:=]\s*["']?0x[a-fA-F0-9]{64}/gi },
  { name: 'Generic secret', pattern: /(?:secret|password|apikey|api_key|auth_token)\s*[:=]\s*["'][^"']{8,}/gi },
  { name: 'Bearer token', pattern: /Bearer\s+[a-zA-Z0-9._\-]{20,}/g },
  { name: 'AWS key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'Hex private key (raw)', pattern: /(?:^|[\s"'=])(?:0x)?[a-fA-F0-9]{64}(?:$|[\s"',])/gm },
];

const SAFE_FILES = [
  '.gitignore',
  'package-lock.json',
  'node_modules',
  '.claude/hooks/pre-push-security.js', // this file itself
];

function isSafeFile(filepath) {
  return SAFE_FILES.some(safe => filepath.includes(safe));
}

function main() {
  try {
    // Get list of files that would be pushed (diff between local and remote)
    const files = execSync('git diff --name-only HEAD @{upstream} 2>/dev/null || git diff --name-only HEAD~5 HEAD 2>/dev/null || echo ""', {
      encoding: 'utf-8',
      cwd: process.cwd(),
    }).trim().split('\n').filter(Boolean);

    if (files.length === 0) {
      process.exit(0);
    }

    let leaks = [];

    for (const file of files) {
      if (isSafeFile(file)) continue;

      try {
        const content = execSync(`git show HEAD:${file} 2>/dev/null`, {
          encoding: 'utf-8',
          maxBuffer: 1024 * 1024, // 1MB max
        });

        for (const { name, pattern } of SECRET_PATTERNS) {
          // Reset regex state
          pattern.lastIndex = 0;
          const matches = content.match(pattern);
          if (matches) {
            // Filter out false positives (short hex strings in contract addresses, etc.)
            const realMatches = matches.filter(m => {
              // Skip known safe contract addresses
              if (m.includes('0x62c64c063ddbcd438f924184c03d8dad45230fa3')) return false;
              if (m.includes('0xaEE532d9707b056f4d0939b91D4031298F7340C0')) return false;
              if (m.includes('0x3cfFEcfdBC7cE87067990b2863dfBBfD1cfD5952')) return false;
              if (m.includes('0x52A0eff814729B98cF75E43d195840CB77ADD941')) return false;
              if (m.includes('0x13b0D85CcB8bf860b6b79AF3029fCA081AE9beF2')) return false;
              return true;
            });
            if (realMatches.length > 0) {
              leaks.push({ file, type: name, count: realMatches.length });
            }
          }
        }
      } catch (e) {
        // File might be binary or deleted, skip
      }
    }

    if (leaks.length > 0) {
      console.error('\n\x1b[31m========================================\x1b[0m');
      console.error('\x1b[31m  AEGIS SECURITY: PUSH BLOCKED\x1b[0m');
      console.error('\x1b[31m========================================\x1b[0m\n');
      console.error('Potential secrets detected in the following files:\n');
      for (const leak of leaks) {
        console.error(`  \x1b[33m${leak.file}\x1b[0m: ${leak.type} (${leak.count} match${leak.count > 1 ? 'es' : ''})`);
      }
      console.error('\nRemove the secrets and try again.');
      console.error('If this is a false positive, review the patterns in .claude/hooks/pre-push-security.js\n');
      process.exit(1);
    }

    console.log('\x1b[32mAegis security check passed\x1b[0m');
    process.exit(0);
  } catch (e) {
    // On error, allow push but warn
    console.error(`\x1b[33mAegis security hook error: ${e.message}\x1b[0m`);
    process.exit(0);
  }
}

main();
