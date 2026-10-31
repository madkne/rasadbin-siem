# Persistent Alert Management

Rasadbin persists detection alerts in the configured GORM database. The existing
WebSocket endpoint (`/ws`) remains the only application API.

## Storage

Startup migration creates:

- `alerts`: detection fields, workflow status, assignee, timestamps, and JSON-encoded evidence.
- `alert_notes`: analyst comments.
- `alert_history`: append-only audit entries for creation, status/assignment changes, and notes.

The migration is additive; existing event, user, and session tables are unchanged.

## Workflow

Supported statuses:

- `new`
- `acknowledged`
- `investigating`
- `resolved`
- `false_positive`

Detection updates refresh title, severity, count, source, timestamps, and evidence,
without overwriting analyst status or assignment. A detection that reappears after
the configured deduplication interval receives a new alert ID, leaving the prior
alert and its investigation history intact.

## WebSocket messages

All messages require an authenticated session.

| Message | Payload | Response |
|---|---|---|
| `alerts.get` | `{search?, severity?, status?, limit?, offset?}` | `alerts`, `alerts.page` |
| `alert.update` | `{id, status, assignee?}` | `alert.updated` broadcast |
| `alert.notes.get` | `{id}` | `alert.notes` |
| `alert.history.get` | `{id}` | `alert.history` |
| `alert.note.add` | `{id, body}` | `alert.note.added` |

`limit` defaults to 200 and is capped at 500. Notes are limited to 10,000 bytes.

## Startup ordering

`SetStore` is called before collector startup so an event cannot produce an alert
before the durable alert repository is attached.

## Tests

Storage tests cover persistence, status/assignee preservation during detection
updates, filtering, notes, and history. Detection tests cover deduplication and
creation of a distinct alert after the deduplication interval.
