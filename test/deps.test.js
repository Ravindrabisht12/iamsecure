import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cvssScore, levelFromScore } from '../src/deps/cvss.js';
import { compareVersions } from '../src/util/semver.js';
import { parseNpmLock } from '../src/deps/lockfiles/npm.js';
import { parseYarnLock } from '../src/deps/lockfiles/yarn.js';
import { parsePnpmLock } from '../src/deps/lockfiles/pnpm.js';
import { parseComposerLock } from '../src/deps/lockfiles/composer.js';
import { parseTomlLock, parseRequirements } from '../src/deps/lockfiles/python.js';
import { normalizeVuln } from '../src/deps/osv.js';

test('CVSS v3 base scores match the spec calculator', () => {
  assert.equal(cvssScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').score, 9.8);
  assert.equal(cvssScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H').score, 7.4);
  assert.equal(cvssScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N').score, 6.1);
  assert.equal(cvssScore('CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N').score, 0);
  assert.equal(cvssScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').score, null);
  assert.equal(levelFromScore(9.0), 'critical');
  assert.equal(levelFromScore(6.9), 'medium');
});

test('version comparison handles prefixes and prereleases', () => {
  assert.equal(compareVersions('4.17.21', '4.17.3'), 1);
  assert.equal(compareVersions('v3.3.0', '3.3.0'), 0);
  assert.equal(compareVersions('1.0.0-beta.1', '1.0.0'), -1);
  assert.equal(compareVersions('2.0', '2.0.0'), 0);
});

test('OSV fix version prefers the range containing the installed version', () => {
  const vuln = {
    id: 'GHSA-test',
    affected: [
      {
        package: { name: 'next', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '13.0.0' }, { fixed: '13.5.9' }, { introduced: '14.0.0' }, { fixed: '14.2.25' }] }],
      },
    ],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' }],
  };
  assert.equal(normalizeVuln(vuln, { name: 'next', version: '13.4.0', ecosystem: 'npm' }).fixedIn, '13.5.9');
  assert.equal(normalizeVuln(vuln, { name: 'next', version: '14.1.0', ecosystem: 'npm' }).fixedIn, '14.2.25');
  assert.equal(normalizeVuln({ id: 'MAL-2025-1', affected: [] }, { name: 'x', version: '1.0.0', ecosystem: 'npm' }).severityScore, 10);
});

const manifest = { dependencies: { app: '^1.0.0' }, devDependencies: { tool: '^2.0.0' } };

test('npm lockfile v3: nested resolution, dev classification, why-path', () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': manifest,
      'node_modules/app': { version: '1.0.0', dependencies: { lib: '^1.0.0' } },
      'node_modules/lib': { version: '1.2.0' },
      'node_modules/tool': { version: '2.0.0', dependencies: { lib: '^2.0.0' } },
      'node_modules/tool/node_modules/lib': { version: '2.0.0', dev: true },
    },
  };
  const g = parseNpmLock(JSON.stringify(lock), manifest);
  assert.equal(g.nodes.get('lib@1.2.0').prod, true);
  assert.equal(g.nodes.get('lib@2.0.0').prod, false);
  assert.deepEqual(g.pathTo('lib@2.0.0'), ['tool@2.0.0', 'lib@2.0.0']);
  assert.equal(g.nodes.get('app@1.0.0').direct, true);
});

test('npm lockfile v1 is converted', () => {
  const lock = {
    lockfileVersion: 1,
    dependencies: {
      app: { version: '1.0.0', requires: { lib: '^1.0.0' } },
      lib: { version: '1.2.0' },
      tool: { version: '2.0.0', dev: true },
    },
  };
  const g = parseNpmLock(JSON.stringify(lock), manifest);
  assert.deepEqual(g.pathTo('lib@1.2.0'), ['app@1.0.0', 'lib@1.2.0']);
  assert.equal(g.nodes.get('tool@2.0.0').prod, false);
});

test('yarn classic and berry lockfiles', () => {
  const classic = `# yarn lockfile v1

app@^1.0.0:
  version "1.0.0"
  dependencies:
    lib "^1.0.0"

lib@^1.0.0:
  version "1.2.0"

tool@^2.0.0:
  version "2.0.0"
`;
  const g1 = parseYarnLock(classic, [{ dir: '.', manifest }]);
  assert.deepEqual(g1.pathTo('lib@1.2.0'), ['app@1.0.0', 'lib@1.2.0']);
  assert.equal(g1.nodes.get('tool@2.0.0').prod, false);

  const berry = `__metadata:
  version: 8

"app@npm:^1.0.0":
  version: 1.0.0
  resolution: "app@npm:1.0.0"
  dependencies:
    lib: "npm:^1.0.0"

"lib@npm:^1.0.0":
  version: 1.2.0
  resolution: "lib@npm:1.2.0"

"my-project@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-project@workspace:."
`;
  const g2 = parseYarnLock(berry, [{ dir: '.', manifest }]);
  assert.deepEqual(g2.pathTo('lib@1.2.0'), ['app@1.0.0', 'lib@1.2.0']);
  assert.equal(g2.nodes.has('my-project@0.0.0-use.local'), false);
});

test('pnpm lockfile v9 with peer suffixes', () => {
  const lock = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      react-dom:
        specifier: 18.2.0
        version: 18.2.0(react@18.2.0)
    devDependencies:
      tool:
        specifier: ^2.0.0
        version: 2.0.0

packages:
  react-dom@18.2.0:
    resolution: {integrity: sha512-x}
  react@18.2.0:
    resolution: {integrity: sha512-y}
  tool@2.0.0:
    resolution: {integrity: sha512-z}

snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
  react@18.2.0: {}
  tool@2.0.0: {}
`;
  const g = parsePnpmLock(lock);
  assert.deepEqual(g.pathTo('react@18.2.0'), ['react-dom@18.2.0', 'react@18.2.0']);
  assert.equal(g.nodes.get('react@18.2.0').prod, true);
  assert.equal(g.nodes.get('tool@2.0.0').prod, false);
});

test('composer.lock (Packagist) strips v-prefix and ignores platform packages', () => {
  const lock = {
    packages: [
      { name: 'guzzlehttp/guzzle', version: '7.4.0', require: { php: '^8', 'guzzlehttp/psr7': '^2', 'ext-json': '*' } },
      { name: 'guzzlehttp/psr7', version: 'v2.1.0' },
    ],
    'packages-dev': [{ name: 'phpunit/phpunit', version: '9.5.0' }],
  };
  const g = parseComposerLock(JSON.stringify(lock), { require: { php: '>=8', 'guzzlehttp/guzzle': '^7' }, 'require-dev': { 'phpunit/phpunit': '^9' } });
  assert.equal(g.ecosystem, 'Packagist');
  assert.deepEqual(g.pathTo('guzzlehttp/psr7@2.1.0'), ['guzzlehttp/guzzle@7.4.0', 'guzzlehttp/psr7@2.1.0']);
  assert.equal(g.nodes.get('phpunit/phpunit@9.5.0').prod, false);
});

test('uv.lock / poetry.lock and requirements.txt (PyPI)', () => {
  const uv = `version = 1

[[package]]
name = "myapp"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "flask" },
]

[[package]]
name = "Flask"
version = "2.0.0"
dependencies = [{ name = "jinja2" }]

[[package]]
name = "jinja2"
version = "2.10"
`;
  const g = parseTomlLock(uv, 'uv.lock', null);
  assert.equal(g.ecosystem, 'PyPI');
  assert.deepEqual(g.pathTo('jinja2@2.10'), ['flask@2.0.0', 'jinja2@2.10']);

  const r = parseRequirements([
    { name: 'requirements.txt', text: 'Django==3.2.0\nflask>=2.0\n# comment\nPyYAML[extra]==5.3 ; python_version > "3"\n' },
    { name: 'requirements-dev.txt', text: 'pytest==6.0.0\n' },
  ]);
  assert.ok(r.nodes.has('django@3.2.0'));
  assert.ok(r.nodes.has('pyyaml@5.3'));
  assert.equal(r.nodes.get('pytest@6.0.0').prod, false);
  assert.equal(r.unpinned, 1);
});
