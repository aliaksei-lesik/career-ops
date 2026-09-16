# Mode: update — ОТКЛЮЧЕН в этом форке

Этот режим намеренно выключен. Если пользователь запускает `/career-ops update` или просит обновить систему — **не обновлять**, а показать содержимое этого файла.

## Почему

Апстримный путь обновления (`update-system.mjs apply`) — примитив удалённого исполнения кода:

1. `git fetch` **изменяемой** ветки `main` — не тега, не пиннутого SHA.
2. `git checkout FETCH_HEAD -- <апдейтер>` — выкладывает только что скачанный код.
3. `execFileSync(process.execPath, ['update-system.mjs', 'apply', '--confirm'])` — **исполняет** его.
4. `execSync('npm install --silent')` — не `npm ci`, то есть с lifecycle-скриптами.

Криптографической верификации нет ни одной. `SYSTEM_PATHS` содержит 315 записей, включая каталог `.github/` целиком — то есть перезаписываются workflows, исполняемые с секретами репозитория.

Разбор целиком — `career-ops-audit.md` §7.1.

## Как обновляться на самом деле

Только руками, человеком, с чтением диффа:

```bash
git fetch upstream main
git log --oneline HEAD..upstream/main     # что приехало
git diff HEAD..upstream/main              # прочитать глазами
git merge upstream/main                   # осознанно
```

Особое внимание — изменениям в `.github/`, `package.json`, `update-system.mjs` и любым новым зависимостям.

## Что технически сделано

- CLI `update-system.mjs` завершается с кодом 1 на любой подкоманде. Экспорты модуля сохранены: из него импортируют 18 файлов, включая валидаторы покрытия и сьют `tests/updater-*.test.mjs`.
- Из `package.json` убраны скрипты `update`, `update:check`, `rollback`. `update:test` оставлен — это тесты самого апдейтера, они продолжают проверять его логику.
- В `AGENTS.md` блок «Update Check» заменён на запрет.
