# Auth Service

## Структура

- `internal/handlers` — Gin-маршруты, JSON, HTTP-коды и JWT middleware. Зависит от `services`.
- `services` — регистрация, проверка пароля, выпуск и проверка JWT, ротация refresh-сессий, правила профиля. Здесь объявлен интерфейс `Repository`.
- `repository` — реализация интерфейса для PostgreSQL. SQL находится только здесь.
- `cmd/auth` — конфигурация, подключение PostgreSQL и сборка зависимостей.
- `migrations` — схема PostgreSQL.

В рабочем запуске используется только `repository.PostgresStore`. Подмены хранилища находятся в `*_test.go` и применяются только в тестах.

## Запуск

Требуется Go 1.25+ и PostgreSQL. Примените `migrations/000001_auth.up.sql` к базе (например, через golang-migrate), задайте `AUTH_DATABASE_URL` и `AUTH_JWT_SECRET` длиной не менее 32 байт, затем выполните `go run ./cmd/auth`. `AUTH_HTTP_ADDR` опционален; по умолчанию `:8080`.

Маршруты: `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET/PATCH /users/me`, `GET /users/:id`, `GET /health/live`, `GET /health/ready`.

Пароли хешируются bcrypt. Access JWT подписывается HS256 и действует 15 минут. Непрозрачный refresh token действует 30 суток; в PostgreSQL хранится только его SHA-256. Повторное использование после ротации и использование после выхода отклоняются.

`GET /users/{id}/articles` зависит от Content Service и пока не реализован. Интеграционный тест с живым PostgreSQL не выполнялся: локальный Docker daemon недоступен.

Проверка: `go test ./... -cover -count=1`, `go vet ./...`.
