// tests/egress-boundary.test.mjs — граница вывода данных существует в КОДЕ,
// а не только в документе.
//
// Форк Timspark. Главный вывод аудита по безопасности апстрима: почти каждое
// заявленное свойство безопасности там — инструкция модели, а не запрет в коде.
// Показательный пример — validate-untrusted-content-coverage.mjs: он грепает
// файлы на наличие строки "Untrusted External Content" и не инспектирует ни
// одного байта данных. Свойство «задокументировано» и не выполняется.
//
// Этот тест написан, чтобы не повторить ту же ошибку с границей вывода данных.
// Он проверяет не наличие комментария, а отсутствие обходного пути:
//
//   1. Ни один раннер не зовёт голый fetch() — весь исходящий трафик идёт через
//      lib/egress-guard.mjs. Один пропущенный call site и граница дырявая.
//   2. Пустой allowlist действительно запрещает, а не пропускает.
//   3. Loopback разрешён всегда: локальная модель выводом данных не является.
//   4. Совпадение по суффиксу требует границы по точке — 'notopenai.com' не
//      должен проходить по правилу 'openai.com'.
//
// Пункт 1 важнее всех: апстрим — живой проект, и мерж может принести новый
// fetch в любой из этих файлов. Тест поймает это на CI, а не на утечке.
//
// Разбор — career-ops-audit.md §7.2.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkEgress, loadEgressAllowlist } from '../lib/egress-guard.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Раннеры, отправляющие cv.md и текст вакансии за пределы машины. */
const RUNNERS = [
  'openai-eval.mjs',
  'openai-tailor.mjs',
  'openrouter-runner.mjs',
  'ollama-eval.mjs',
];

test('no runner calls bare fetch() — every request goes through the guard', () => {
  const offenders = [];
  for (const file of RUNNERS) {
    const src = readFileSync(join(ROOT, file), 'utf-8');
    src.split('\n').forEach((line, i) => {
      // guardedFetch(/egressFetch( тоже содержат "fetch(", поэтому требуем,
      // чтобы перед ним не было буквы, цифры, точки или подчёркивания.
      if (/(?<![\w.])fetch\s*\(/.test(line)) offenders.push(`${file}:${i + 1}: ${line.trim()}`);
    });
  }
  assert.deepEqual(
    offenders, [],
    'these lines call fetch() directly, bypassing lib/egress-guard.mjs. An upstream ' +
      'merge most likely brought them in. Route them through guardedFetch/egressFetch — ' +
      'one missed call site is the whole boundary (career-ops-audit.md §7.2):\n  ' +
      offenders.join('\n  '),
  );
});

test('every runner imports the guard', () => {
  for (const file of RUNNERS) {
    const src = readFileSync(join(ROOT, file), 'utf-8');
    assert.match(src, /egress-guard\.mjs/, `${file} no longer imports the egress guard`);
  }
});

test('gemini runners guard the SDK client they cannot route through fetch', () => {
  for (const file of ['gemini-eval.mjs', 'batch-evaluate-gemini.mjs']) {
    const src = readFileSync(join(ROOT, file), 'utf-8');
    assert.match(
      src, /assertEgressAllowed\(\s*'generativelanguage\.googleapis\.com'/,
      `${file} constructs the Gemini SDK client without asserting egress first`,
    );
  }
});

test('the shipped allowlist is empty — deny by default', () => {
  const { allow } = loadEgressAllowlist();
  assert.deepEqual(
    allow, [],
    'config/llm-endpoints.json ships with a non-empty allowlist. Approving a ' +
      'subprocessor for employee CVs is a company decision, not a repo default.',
  );
});

test('an empty allowlist blocks a real provider', () => {
  assert.equal(checkEgress('https://api.openai.com/v1/chat/completions', []).allowed, false);
  assert.equal(checkEgress('generativelanguage.googleapis.com', []).allowed, false);
});

test('loopback is always allowed — a local model is not egress', () => {
  for (const url of ['http://localhost:11434', 'http://127.0.0.1:8080', 'http://[::1]:1234']) {
    const r = checkEgress(url, []);
    assert.equal(r.allowed, true, `${url} should be allowed with an empty allowlist`);
    assert.equal(r.loopback, true, `${url} should be recognised as loopback`);
  }
});

test('suffix matching respects the dot boundary', () => {
  assert.equal(checkEgress('https://api.openai.com', ['openai.com']).allowed, true);
  assert.equal(checkEgress('https://openai.com', ['openai.com']).allowed, true);
  // The one that matters: a lookalike domain must not ride in on a suffix match.
  assert.equal(checkEgress('https://notopenai.com', ['openai.com']).allowed, false);
  assert.equal(checkEgress('https://openai.com.evil.test', ['openai.com']).allowed, false);
});

test('an unparseable target is refused, not waved through', () => {
  assert.equal(checkEgress('not a url at all', ['openai.com']).allowed, false);
});

test('the policy is not settable from the data root', () => {
  // The bypass this closes: loadEgressAllowlist() resolved the file under
  // getCareerOpsRoot(), and that root comes from CAREER_OPS_ROOT — chosen by
  // whoever runs the script. Pointing it at a directory holding a permissive
  // llm-endpoints.json lifted the boundary without touching a reviewed file,
  // which is the opposite of the property this module claims. Found by running
  // the renderer against a separate candidate root, where the guard reported
  // the shipped config as "отсутствует".
  const tmp = mkdtempSync(join(tmpdir(), 'egress-root-'));
  mkdirSync(join(tmp, 'config'), { recursive: true });
  writeFileSync(
    join(tmp, 'config', 'llm-endpoints.json'),
    JSON.stringify({ allow: ['evil.test'] }),
  );
  const saved = process.env.CAREER_OPS_ROOT;
  process.env.CAREER_OPS_ROOT = tmp;
  try {
    assert.deepEqual(
      loadEgressAllowlist().allow, [],
      'CAREER_OPS_ROOT changed the effective allowlist. The policy must come ' +
        'from the checkout, where it is under review, not from a data root.',
    );
  } finally {
    if (saved === undefined) delete process.env.CAREER_OPS_ROOT;
    else process.env.CAREER_OPS_ROOT = saved;
    rmSync(tmp, { recursive: true, force: true });
  }
});
