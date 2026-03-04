# DynamoDB Provider

The DynamoDB provider stores configuration in a single DynamoDB table using a PK/SK (partition key / sort key) design pattern.

## Feature Flag

```bash
cargo build -p multistore-server --features multistore/config-dynamodb
```

## Usage

```rust
use multistore::config::dynamodb::DynamoDbProvider;

let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
let client = aws_sdk_dynamodb::Client::new(&aws_config);
let provider = DynamoDbProvider::new(client, "multistore-proxy-config".to_string());
```

## Table Design

The provider uses a single-table design with partition key (`PK`) and sort key (`SK`) attributes.

## When to Use

- AWS-native infrastructure
- Serverless deployments where a database server isn't practical
- High-availability requirements (DynamoDB's built-in replication)

> [!TIP]
> Wrap the DynamoDB provider with [CachedProvider](./cached) to reduce read costs and latency.
