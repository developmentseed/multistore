# PostgreSQL Provider

::: warning Planned — not yet implemented
This config provider is a planned feature and does not exist in the current release. The API shown here is a design sketch and is subject to change. The only built-in config provider today is the [static file provider](./static-file.md).
:::

The PostgreSQL provider would store configuration in a PostgreSQL database (e.g. via sqlx). The sketch below illustrates the intended usage.

## Usage (design sketch)

The intended constructor would look like:

```rust
use multistore::config::postgres::PostgresProvider;

let pool = sqlx::PgPool::connect("postgres://localhost/s3proxy").await?;
let provider = PostgresProvider::new(pool);
```

## When to Use

- Existing PostgreSQL infrastructure
- Relational data management preferences
- Complex queries or joins with other application data

> [!TIP]
> Wrap the PostgreSQL provider with [CachedProvider](./cached) to reduce query load and latency.
