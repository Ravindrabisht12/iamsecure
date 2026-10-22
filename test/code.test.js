import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { stripComments } from '../src/code/strip.js';
import { scanFile, taintedNames } from '../src/code/engine.js';
import { classifyFile, extractImports, packageOf } from '../src/code/context.js';
import { scanSecrets } from '../src/code/secrets.js';

const rules = (file, code, ctx = 'server') => scanFile(file, code, ctx).map((f) => f.ruleId);

test('comments are blanked but strings and URLs survive', () => {
  const out = stripComments("const u = 'http://x.io'; // eval(a)\n/* exec(b) */ run();", 'js');
  assert.match(out, /http:\/\/x\.io/);
  assert.doesNotMatch(out, /eval|exec/);
  assert.equal(out.split('\n').length, 2);
  assert.doesNotMatch(stripComments('x = 1  # os.system(y)', 'py'), /system/);
});

test('taint tracking follows assignments and destructuring', () => {
  const names = taintedNames("const { file } = req.query;\nconst p = '/tmp/' + file;\nconst safe = 'x';", 'js');
  assert.ok(names.has('file') && names.has('p'));
  assert.ok(!names.has('safe'));
});

test('JS rules: tainted sinks fire, constants and comments do not', () => {
  const code = `import { exec } from 'child_process';
const name = req.query.name;
exec(\`ls \${name}\`);
exec('ls -la');
// exec(\`rm \${name}\`)
db.query(\`SELECT * FROM t WHERE id = \${name}\`);
db.query('SELECT * FROM t WHERE id = $1', [name]);
fetch(req.body.url);
fetch('https://api.example.com/x');
el.innerHTML = '<b>static</b>';
el.innerHTML = name;
`;
  const hits = scanFile('api/x.js', code, 'server');
  const byLine = Object.fromEntries(hits.map((h) => [h.location.line, h.ruleId]));
  assert.equal(byLine[3], 'js-command-injection');
  assert.equal(byLine[4], undefined);
  assert.equal(byLine[5], undefined);
  assert.equal(byLine[6], 'js-sql-injection');
  assert.equal(byLine[7], undefined);
  assert.equal(byLine[8], 'js-ssrf');
  assert.equal(byLine[9], undefined);
  assert.equal(byLine[10], undefined);
  assert.equal(byLine[11], 'js-xss-inner-html');
  assert.equal(hits.find((h) => h.location.line === 3).severity, 'critical');
});

test('PHP and Python rules respect sanitisers and safe APIs', () => {
  assert.deepEqual(rules('a.php', '<?php echo htmlspecialchars($_GET["q"]);'), []);
  assert.deepEqual(rules('a.php', '<?php echo "Hi " . $_GET["q"];'), ['php-xss-echo']);
  assert.deepEqual(rules('a.php', "<?php require 'vendor/autoload.php';"), []);
  assert.deepEqual(rules('a.py', 'cfg = yaml.safe_load(data)'), []);
  assert.deepEqual(rules('a.py', 'subprocess.run(["ls", "-la"])'), []);
  assert.deepEqual(rules('a.py', 'cursor.execute("SELECT 1 WHERE a = %s", (a,))'), []);
  assert.deepEqual(rules('a.py', 'cursor.execute(f"SELECT 1 WHERE a = {a}")'), ['py-sql-injection']);
});

test('file context classification', () => {
  assert.equal(classifyFile('app/api/users/route.ts', '', 'next'), 'server');
  assert.equal(classifyFile('app/page.tsx', '', 'next'), 'server');
  assert.equal(classifyFile('components/Btn.tsx', "'use client';\nexport default 1", 'next'), 'client');
  assert.equal(classifyFile('pages/index.tsx', '', 'next'), 'universal');
  assert.equal(classifyFile('src/App.tsx', '', 'vite-spa'), 'client');
  assert.equal(classifyFile('src/app.test.ts', '', 'next'), 'build');
  assert.equal(classifyFile('next.config.js', '', 'next'), 'build');
  assert.equal(classifyFile('index.php', '', 'php'), 'server');
});

test('import extraction finds package names and bindings', () => {
  const imps = extractImports(`import _ from 'lodash';\nimport { a } from '@scope/pkg/sub';\nconst jwt = require('jsonwebtoken');\nimport x from './local';\nimport fs from 'node:fs';`);
  assert.deepEqual(imps.map((i) => [i.pkg, i.binding]), [['lodash', '_'], ['@scope/pkg', null], ['jsonwebtoken', 'jwt']]);
  assert.equal(packageOf('@/components/x'), null);
});

test('secrets: real-looking keys found and masked, placeholders ignored', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iamsecure-'));
  const files = [
    { rel: 'a.js', kind: 'code', text: "const k = 'ghp_" + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8' + "';" },
    { rel: 'b.js', kind: 'code', text: "const password = 'changeme';\nconst apiKey = process.env.API_KEY;" },
    { rel: 'c.js', kind: 'code', text: "const db_password = 'x9F!qL2#vB7m';" },
  ];
  const src = { files, texts: new Map(files.map((f) => [f.rel, f.text])), contexts: new Map(files.map((f) => [f.rel, 'server'])) };
  const found = scanSecrets(src, dir);
  assert.deepEqual(found.map((f) => f.ruleId).sort(), ['secret-generic-secret', 'secret-github-token']);
  assert.doesNotMatch(found.find((f) => f.ruleId === 'secret-github-token').location.snippet, /O5p6Q7r8/);
  fs.rmSync(dir, { recursive: true });
});
