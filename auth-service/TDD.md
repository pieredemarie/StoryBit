# TDD: разделение Auth Service на слои

Источник: задачи 2.1–2.4 из `D:\PetProjects\StoryBit\tasks.md` и требование пользователя разделить код на `internal/handlers`, `services`, `repository`.

| Слой | RED | GREEN |
|---|---|---|
| `services` | `go test ./services -run TestRegisterLoginRefreshLogout -count=1`: отсутствовали `User`, `NewAuthService` и сервисные ошибки | `go test ./services -run TestRegisterLoginRefreshLogout -count=1`: PASS |
| `repository` | Код перенесён из `internal/server`; до исправления типа пользователя `go test ./repository -count=1` падал на `u.Hash undefined` | `go test ./repository -count=1`: PASS |
| `internal/handlers` | `go test ./internal/handlers -run TestAuthJourney -count=1`: отсутствовал `NewForTest` | `go test ./internal/handlers -count=1`: PASS |

Итоговая проверка: `go test ./... -cover -count=1` и `go vet ./...`. Покрытие: handlers — 82.3%, services — 90.3%, repository — 90.9%; точка входа `cmd/auth` тестами не покрыта. SQL-контракт проверен с mock-драйвером. Интеграционный запуск с живым PostgreSQL остаётся открытым из-за недоступного Docker daemon. Git checkpoint-коммитов нет: каталог не является Git-репозиторием.
