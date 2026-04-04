# gRPC Subscribe Filter Plugin for Pingap

## Что это

Плагин `grpc_subscribe_filter` для Pingap, который валидирует и ограничивает параметры gRPC подписок (`SubscribeRequest`) к **Yellowstone/Geyser** (Solana). Работает как прокси-уровневый фаервол для gRPC streaming.

## Зачем

Yellowstone gRPC позволяет клиентам подписываться на события блокчейна (аккаунты, транзакции, блоки). Без ограничений клиент может:
- Подписаться на слишком много аккаунтов/владельцев, перегрузив ноду
- Подписаться на "тяжёлые" аккаунты (Token Program и т.д.)
- Запросить include_accounts/include_entries в блоках, что даёт огромный трафик

Плагин решает это на уровне прокси, до того как запрос дойдёт до ноды.

## Что изменено

### Новые файлы
| Файл | Описание |
|------|----------|
| `pingap-plugin/src/grpc_subscribe_filter.rs` | Плагин: per-IP правила, protobuf парсер, валидация |
| `conf/grpc-subscribe-filter.toml` | Конфигурация плагина (rules_dir) |
| `<rules_dir>/<IP>.toml` | Per-IP правила (создаются вручную) |

### Изменённые файлы
| Файл | Что изменено |
|------|-------------|
| `pingap-core/src/plugin.rs` | Добавлен метод `handle_request_body()` в trait Plugin |
| `pingap-proxy/src/server.rs` | Добавлен `handle_request_body_plugin()` + вызов из `request_body_filter()` |
| `pingap-plugin/src/lib.rs` | Добавлен `mod grpc_subscribe_filter` |

## Архитектурные решения

### 1. Расширение Plugin trait
Plugin trait не имел доступа к телу запроса. Добавлен `handle_request_body()`:
```rust
fn handle_request_body(
    &self, session, ctx, body, end_of_stream
) -> pingora::Result<Option<HttpResponse>>
```
- `None` — пропустить запрос
- `Some(HttpResponse)` — отклонить запрос

### 2. Ручной парсинг protobuf
Вместо зависимости на `prost` / `yellowstone-grpc-proto` — парсим protobuf wire format вручную:
- Читаем varint тег → определяем field number + wire type
- Для нужных полей (map, repeated string) извлекаем значения
- Остальные поля пропускаем по wire type

Это даёт: ноль внешних зависимостей, быстрый парсинг, но хрупкость при изменении proto.

### 3. Двухфазная обработка
1. `handle_request` (step=Request) — проверяет path == `/geyser.Geyser/Subscribe`, сохраняет client IP в ctx
2. `handle_request_body` — если флаг стоит, получает per-IP правила, парсит gRPC frame и валидирует

### 4. Per-IP правила из файлов
Правила загружаются из TOML файлов в `rules_dir`:
- `<IP>.toml` — правила для конкретного IP (e.g. `192.168.1.10.toml`)
- **Нет файла для IP → reject (FORBIDDEN).** Default правил нет — только явно разрешённые IP.
- Перечитываются каждые `reload_interval` (default: 30s) без перезапуска
- Для добавления клиента — создать файл `<IP>.toml`, плагин подхватит при следующем reload
- Для блокировки клиента — удалить его файл

## Конфигурация

### Плагин (conf/grpc-subscribe-filter.toml)
```toml
[plugins.grpcSubscribeFilter]
category = "grpc_subscribe_filter"
rules_dir = "conf/grpc-filters"    # директория с per-IP правилами
reload_interval = "30s"             # интервал перечитывания
```

### Per-IP файл (conf/grpc-filters/192.168.1.10.toml)
```toml
[accounts]
account_max = 40
owner_max = 200
data_slice_max = 3
account_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
owner_reject = ["11111111111111111111111111111111"]

[transactions]
account_include_max = 30
account_exclude_max = 20
account_required_max = 40
account_include_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]

[blocks]
account_include_max = 500
include_accounts = false
include_entries = false
include_transactions = true
account_include_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]

[transactions_status]
account_include_max = 200
account_exclude_max = 20
account_required_max = 200
account_include_reject = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
```

### Значения по умолчанию (если секция/ключ не указаны)

| Секция | Параметр | По умолчанию |
|--------|----------|-------------|
| `accounts` | `account_max` | 100 |
| `accounts` | `owner_max` | 20 |
| `accounts` | `data_slice_max` | 2 |
| `transactions` | `account_include_max` | 100 |
| `transactions` | `account_exclude_max` | 100 |
| `transactions` | `account_required_max` | 100 |
| `blocks` | `account_include_max` | 20 |
| `blocks` | `include_transactions` | true |
| `blocks` | `include_accounts` | false |
| `blocks` | `include_entries` | false |
| `transactions_status` | `*_max` | 20 |

### Подключение к location

```toml
[locations.grpc]
path = "/"
upstream = "solana-grpc"
plugins = ["grpcSubscribeFilter"]
```

## Protobuf field mapping

```
SubscribeRequest:
  field 1  → accounts (map)
  field 3  → transactions (map)
  field 4  → blocks (map)
  field 7  → accounts_data_slice (repeated)
  field 10 → transactions_status (map)

FilterAccounts:
  field 2 → account (repeated string)
  field 3 → owner (repeated string)

FilterTransactions:
  field 3 → account_include (repeated string)
  field 4 → account_exclude (repeated string)
  field 6 → account_required (repeated string)

FilterBlocks:
  field 1 → account_include (repeated string)
  field 2 → include_transactions (bool)
  field 3 → include_accounts (bool)
  field 4 → include_entries (bool)
```

## Известные ограничения

1. **Первый чанк** — плагин валидирует только первый body chunk. Если SubscribeRequest фрагментирован на несколько HTTP/2 DATA frames, валидация может быть неполной.
2. **Сжатие** — если gRPC compression включён (первый байт = 1), protobuf не распарсится. Сейчас сжатие не обрабатывается.
3. **Proto изменения** — при обновлении Yellowstone proto (изменение field numbers) парсер нужно обновить вручную.
4. **HTTP/2 trailers** — Pingora 0.8.0 может не полностью проксировать gRPC trailers, но на практике streaming работает.

## Рекомендации по конфигу для low-latency gRPC proxy

```toml
# upstreams
[upstreams.solana-grpc]
addrs = ["127.0.0.1:10000"]
alpn = "H2"
idle_timeout = "30m"          # default 60s — слишком часто reconnect
connection_timeout = "5s"
read_timeout = "300s"
tcp_idle = "30s"              # TCP keepalive: обнаружение мёртвых соединений
tcp_interval = "10s"
tcp_probe_count = 3

# basic
[basic]
upstream_keepalive_pool_size = 256   # default 128
log_level = "warn"
```

**Что НЕ включать:**
- `access_log` — I/O overhead на каждый запрос
- `prometheus_metrics` — метрики на каждый запрос
- `modules = ["grpc-web"]` — не нужен для нативного gRPC
- compression plugin — gRPC имеет свою компрессию
- `PINGAP_DISABLE_ACME=1` — если статические сертификаты

## Ветка

`feature/grpc-subscribe-filter`
