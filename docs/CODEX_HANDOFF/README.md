# Codex handoff

Состояние зафиксировано для передачи дальнейшей разработки Codex.

Точка отсчёта:

- Repository: `detestern/KarinCore` (branch `android`)
- Branch: `main`
- Version: `0.1.0-alpha.31`
- Android versionCode: `31`
- Release code baseline: tag `v0.1.0-alpha.31`
- Upstream base: `detestern/KarinCore` 1.3.7, commit `b7fea2e2ff5e1492fd863381985fdebb4da7a57e`
- Current Android release: `v0.1.0-alpha.31`
- Current release APKs: split debug builds for `arm64-v8a`, `armeabi-v7a`, `x86` and `x86_64`
- Repository checks: passing
- Android CI build: passing

Документы:

1. [PROJECT_STATE.md](PROJECT_STATE.md) - полный снимок текущего состояния.
2. [TECHNICAL_ARCHITECTURE.md](TECHNICAL_ARCHITECTURE.md) - архитектура, потоки данных и критичные инварианты.
3. [ROADMAP.md](ROADMAP.md) - план дальнейшей разработки и критерии готовности.
4. [CODEX_PROMPT.md](CODEX_PROMPT.md) - готовая инструкция для продолжения проекта в Codex.

После release baseline в `main` могут находиться documentation-only commits. При расхождении документации и актуального кода источником истины является текущий `main`. Перед любой работой необходимо проверить `VERSION`, `CHANGELOG.md`, последние коммиты и статус CI.
