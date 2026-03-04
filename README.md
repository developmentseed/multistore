# MultiStore

MultiStore is an application to easily create an S3-compliant API for one-or-many object store backends.

The system could be utilized to...

1. create custom access credentials (distinct from AWS credentials) to be given out to grant access
2. collect detailed usage metrics
3. gate access to datasets
4. bill users for dataset access

## Configuration

### Setting up credentials

1. Copy the example configuration:
   ```sh
   cp database.example.yaml database.yaml
   ```

2. Edit `database.yaml` with your actual credentials:
   - **data-sources**: Configure the S3 buckets you want to proxy
   - **credentials**: Define user credentials for accessing your API

**⚠️ Important**: Never commit `database.yaml` to git - it contains sensitive credentials!

### For Cloudflare Workers deployment

The CF Workers deployment uses environment variables for configuration:

1. Create a GitHub secret called `DATABASE_CONFIG` containing your `database.yaml` contents
2. Set up these additional secrets in your GitHub repository:
   - `CLOUDFLARE_API_TOKEN`: Your Cloudflare API token
   - `CLOUDFLARE_ACCOUNT_ID`: Your Cloudflare account ID

The deployment workflow will automatically inject the configuration as an environment variable.

## Development

### Running Hyper API

```sh
cargo run --bin hyper-api
```

### Running Cloudflare Workers API

```sh
npx wrangler dev --cwd examples/cf-workers-api
```

### Running Lambda API

Lambda execution makes use of the [aws-lambda-rust-runtime](https://github.com/awslabs/aws-lambda-rust-runtime).

```sh
cargo lambda watch --bin lambda-api
```

### Accessing the API

```sh
export AWS_MAX_ATTEMPTS=1
export AWS_EC2_METADATA_DISABLED=true
export ENDPOINT_URL=http://localhost:9000/lambda-url/lambda-api
export AWS_ACCESS_KEY_ID=foo 
export AWS_SECRET_ACCESS_KEY=bar
```

```sh
aws \
--endpoint-url ${ENDPOINT_URL} \
--no-cli-pager \
s3api list-buckets
```
