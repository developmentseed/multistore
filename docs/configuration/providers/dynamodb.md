# DynamoDB Provider

::: warning Planned — not yet implemented
This config provider is a planned feature and does not exist in the current release. The API shown here is a design sketch and is subject to change. The only built-in config provider today is the [static file provider](./static-file.md).
:::

The DynamoDB provider would store configuration in a single DynamoDB table using a PK/SK (partition key / sort key) design pattern. The sketch below illustrates the intended usage.

## Usage (design sketch)

The intended constructor would look like:

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
