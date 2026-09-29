// lib/egress-guard.mjs — единая граница вывода данных за пределы машины.
//
// Форк Timspark. Контекст: career-ops рассчитан на одного соискателя, который
// сам решает, куда отправить собственное резюме. Мы держим десятки корней
// данных с резюме сотрудников, поэтому «куда уходит cv.md» — не пользовательская
// настройка, а решение компании.
//
// В апстриме этой границы нет: `openai-eval.mjs` и `openai-tailor.mjs` шлют
// cv.md вместе с полным текстом вакансии на ЛЮБОЙ адрес из OPENAI_BASE_URL.
// Одна правка .env молча добавляет субпроцессора по GDPR. Авторы честно пишут
// это в шапке файла, но кодом не ограничивают. Разбор — career-ops-audit.md §7.2.
//
// Модель по умолчанию — запретительная: не разрешено ничего, кроме loopback.
// Локальная модель (Ollama, LM Studio, llama.cpp, vLLM на 127.0.0.1) выводом
// данных не является и разрешена всегда.
//
// Паттерн заимствован у ollama-eval.mjs, который единственный в апстриме делает
// это правильно: loopback свободно, удалённый адрес — только явным решением.
//
// Разрешить провайдера: lib/egress-policy.mjs, список ALLOW.

import { ALLOW, POLICY_SOURCE } from './egress-policy.mjs';

// Политика импортируется из checkout'а, а не читается из getCareerOpsRoot().
// Корень данных задаётся переменной CAREER_OPS_ROOT, то есть выбирается тем же,
// кто запускает скрипт: разрешающий файл в собственном каталоге снимал бы
// границу целиком. Первая версия хранила список в config/llm-endpoints.json и
// ровно этим и страдала. Побочно импорт избавляет от копирования политики в
// каждый корень кандидата и от ветки «JSON не разобран».

/** Хосты, обращение к которым не является выводом данных за пределы машины. */
const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0']);

/**
 * Действующий allowlist. Всё, что не строка, отбрасывается: список правится
 * руками, и правка вида ALLOW = ['api.openai.com', null] не должна превращаться
 * в разрешение неизвестно чего.
 *
 * @returns {{allow: string[], source: string}}
 */
export function loadEgressAllowlist() {
  const allow = Array.isArray(ALLOW) ? ALLOW.filter(x => typeof x === 'string' && x.trim()) : [];
  return { allow, source: POLICY_SOURCE };
}

/**
 * Разрешён ли адрес. Сравнение по хосту, без учёта схемы, порта и пути:
 * allowlist — это перечень сторон, которым мы доверяем данные, а не URL.
 *
 * @param {string} target URL или голое имя хоста
 * @param {string[]} allow
 * @returns {{allowed: boolean, host: string|null, loopback: boolean}}
 */
export function checkEgress(target, allow) {
  let host;
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? target : `https://${target}`).hostname;
  } catch {
    return { allowed: false, host: null, loopback: false };
  }
  const bare = host.replace(/^\[|\]$/g, '');
  if (LOOPBACK.has(host) || LOOPBACK.has(bare)) return { allowed: true, host, loopback: true };
  // Точное совпадение хоста либо поддомен разрешённого домена.
  const allowed = allow.some(a => {
    const h = String(a).trim().toLowerCase();
    return h && (host.toLowerCase() === h || host.toLowerCase().endsWith(`.${h}`));
  });
  return { allowed, host, loopback: false };
}

/**
 * Проверить и, если не разрешено, завершить процесс с объяснением.
 * Вызывать ДО сборки промпта и до любого чтения cv.md, чтобы отказ был дешёвым
 * и очевидным.
 *
 * @param {string} target URL эндпоинта или имя хоста провайдера
 * @param {{script?: string, what?: string}} [opts]
 */
export function assertEgressAllowed(target, opts = {}) {
  const script = opts.script || 'this script';
  const what = opts.what || 'ваш cv.md и полный текст вакансии';
  const { allow, source } = loadEgressAllowlist();
  const { allowed, host, loopback } = checkEgress(target, allow);
  if (allowed) return { host, loopback };

  console.error([
    '',
    `career-ops: egress BLOCKED — ${script}`,
    '',
    host
      ? `  Адрес назначения: ${host}`
      : `  Не удалось разобрать адрес назначения: ${JSON.stringify(target)}`,
    `  Было бы отправлено: ${what}`,
    '',
    `  Этот хост не значится в allowlist (${source}).`,
    '',
    '  В форке Timspark граница вывода данных закреплена кодом: резюме',
    '  сотрудников не уходят на адрес, который никто не утверждал.',
    '  Разбор — career-ops-audit.md §7.2.',
    '',
    '  Разрешить осознанно:',
    `    ${POLICY_SOURCE}  ->  export const ALLOW = ['${host || 'example.com'}'];`,
    '',
    '  Локальная модель (127.0.0.1 / localhost) разрешена всегда и в',
    '  allowlist не нуждается.',
    '',
  ].join('\n'));
  process.exit(1);
}

/**
 * fetch, проходящий через границу вывода данных.
 *
 * Почему обёртка, а не вызов assertEgressAllowed рядом с каждым fetch:
 *  - проверка происходит в МОМЕНТ ВЫЗОВА, а не при импорте модуля. Гард на
 *    уровне модуля убивал процесс при простом `import` файла — ломались тесты,
 *    которые подгружают раннер, чтобы посмотреть на его константы;
 *  - потерять call site невозможно: `grep -n 'await fetch('` по раннеру должен
 *    давать пусто, и это проверяемо в CI.
 *
 * @param {string|URL} url
 * @param {RequestInit} [init]
 * @param {{script?: string, what?: string}} [opts]
 * @returns {Promise<Response>}
 */
export async function guardedFetch(url, init, opts = {}) {
  assertEgressAllowed(String(url), opts);
  return fetch(url, init);
}

/**
 * Связать guardedFetch с именем скрипта один раз на модуль.
 *
 * Иначе имя пришлось бы протаскивать в каждый из девяти вызовов, и забытый
 * аргумент дал бы бесполезное «this script» ровно тогда, когда нужно понять,
 * что именно упёрлось в границу. Выводить имя из process.argv[1] нельзя:
 * конвенция репозитория запрещает читать путь точки входа вне
 * lib/is-main-module.mjs (#3170, tests/main-guard-convention.test.mjs).
 *
 * @param {string} script Имя файла для сообщения об отказе
 * @param {{what?: string}} [defaults]
 * @returns {(url: string|URL, init?: RequestInit) => Promise<Response>}
 */
export function egressFetch(script, defaults = {}) {
  return (url, init) => guardedFetch(url, init, { script, ...defaults });
}
