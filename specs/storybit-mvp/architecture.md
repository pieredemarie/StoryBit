# Границы сервисов и события

Статус: проект контракта, требует утверждения вместе с решениями в `decisions.md`.

## Владение данными

| Сервис | Собственные данные | Публичный интерфейс |
|---|---|---|
| Auth | users, refresh_sessions | регистрация, токены, профиль; внутренний batch lookup автора по UUID |
| Content | bits, bit_versions, articles, article_revisions, article_bits, draft_article_bits, tags, article_tags, outbox_events | публикация, чтение, снимок для переиндексации |
| Search | индекс опубликованных статей, processed_events | поиск |
| Notification | уведомления, processed_events | список и отметка прочтения |

Сервисы не читают чужие таблицы. Content хранит UUID автора. Публичные имена авторов для чтения Content запрашивает у Auth по внутреннему batch API с коротким кэшем; Search получает денормализованное имя через snapshot события публикации и обновляет его при `user.profile_updated`. Для переиндексации Search получает снимки через Content API, а имена — через Auth API. Доступ к внутренним API ограничить сетью сервисов и сервисной аутентификацией.

## Конверт события

`event_id` (UUID), `event_type` (строка), `occurred_at` (UTC ISO 8601), `schema_version` (целое, начиная с 1), `aggregate_id` (UUID), `aggregate_version` (целое), `payload` (объект). Kafka key = `aggregate_id`. Публикация через transactional outbox в той же транзакции, что изменение Content.

| Событие | Payload v1 | Получатель |
|---|---|---|
| article.published / article.updated | article_id, revision, author_id, title, tags, published_at | Search |
| article.deleted | article_id, revision | Search |
| bit.cited | article_id, revision, bit_id, bit_version, bit_author_id, citing_author_id, source_article_id, source_revision | Notification |
| user.profile_updated | user_id, username | Search |

Поиск и уведомления используют таблицу `processed_events` с уникальным `event_id`; обработка события и запись маркера — одна транзакция. Повторы безопасны. Для Search применять событие только если `aggregate_version` выше сохранённой версии; старые события игнорировать. Временные ошибки повторять с backoff, необрабатываемые события отправлять в Dead Letter Topic с причиной. Поиск имеет eventual consistency; успешный ответ публикации не обещает немедленную видимость в поиске. Для полной переиндексации Search постранично получает опубликованные актуальные редакции через Content API, строит новую генерацию индекса и атомарно переключает её.

## Открытые детали перед реализацией

- Период хранения outbox и processed_events, сроки retry и максимальный лаг поиска.
- Схема внутренней аутентификации и TTL кэша имён.
- Семантика `bit.cited`: одно событие на уникальную цитату в опубликованной редакции; самоуведомления не создавать.

