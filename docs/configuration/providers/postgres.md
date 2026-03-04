# PostgreSQL Provider

The PostgreSQL provider stores configuration in a PostgreSQL database using sqlx.

## Feature Flag

```bash
cargo build -p multistore-server --features multistore/config-postgres
```

## Usage

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
