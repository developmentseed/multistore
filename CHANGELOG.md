# Changelog

## [0.4.0](https://github.com/developmentseed/multistore/compare/v0.3.1...v0.4.0) (2026-04-07)


### Features

* **oidc:** support multiple signing keys ([#26](https://github.com/developmentseed/multistore/issues/26)) ([ead26d8](https://github.com/developmentseed/multistore/commit/ead26d8a5e5290492ed8b3fd93a4b9573ff03d64))
* **sts:** enable custom STS endpoint URL ([#32](https://github.com/developmentseed/multistore/issues/32)) ([ff12fe3](https://github.com/developmentseed/multistore/commit/ff12fe37ea38f1da9d96d98e7412cc46ffbecef8))

## [0.3.1](https://github.com/developmentseed/multistore/compare/v0.3.0...v0.3.1) (2026-03-31)


### Bug Fixes

* directory marker support ([#22](https://github.com/developmentseed/multistore/issues/22)) ([7e7b487](https://github.com/developmentseed/multistore/commit/7e7b48724c4329009156a50a6c796cdcae95f165))

## [0.3.0](https://github.com/developmentseed/multistore/compare/v0.2.0...v0.3.0) (2026-03-24)


### Features

* **cf-workers:** streamline response handling and header conversion ([80f8543](https://github.com/developmentseed/multistore/commit/80f8543122a43367f1341329eb7d57104692bcb3))
* **core:** support ListObjectsV1 ([1d61dfc](https://github.com/developmentseed/multistore/commit/1d61dfc401110776e53be80ace1dfd0bf2bb793c))
* **path-mapping:** add more convenience tooling ([9c4f5bb](https://github.com/developmentseed/multistore/commit/9c4f5bbb84d903845f50af059efcc55288a788b9))


### Bug Fixes

* **cf-workers:** disable retry on buckets to avoid WASM panic ([804b0bb](https://github.com/developmentseed/multistore/commit/804b0bb9903b3c958f0f50f78de53fe934270ce9))
* **core:** support custom backend response headers ([a5c5b9f](https://github.com/developmentseed/multistore/commit/a5c5b9f794fd113b66df11d0302c0490b02b6160))

## [0.2.0](https://github.com/developmentseed/multistore/compare/multistore-v0.1.1...multistore-v0.2.0) (2026-03-19)


### Features

* add display_name field to ResolvedBucket ([263d324](https://github.com/developmentseed/multistore/commit/263d324fe417a9bb9a4d04fcac9b029688d7be19))
* add metering middleware ([20395f7](https://github.com/developmentseed/multistore/commit/20395f74def521b4ee74260e8cc8e399e81be25c))
* add metering middleware ([73c2d2c](https://github.com/developmentseed/multistore/commit/73c2d2cdc9dd28606b2da0e4217e222881c05600))
* add OidcDiscoveryRouteHandler for .well-known endpoints ([d5f01a0](https://github.com/developmentseed/multistore/commit/d5f01a0e9b52ce92e9c309f03b48c99adc3ef11a))
* add RouteHandler trait and RequestInfo for pluggable pre-dispatch routing ([1db06a8](https://github.com/developmentseed/multistore/commit/1db06a873b4af645082899520c14439d5b419202))
* add StsRouteHandler for AssumeRoleWithWebIdentity interception ([c6d6d66](https://github.com/developmentseed/multistore/commit/c6d6d66fb908d8471f0e607b1f8ded10b916f30e))
* **cf-workers:** add azure/gcp feature flags for StoreBuilder variants ([61aa2f5](https://github.com/developmentseed/multistore/commit/61aa2f53e4ba6c9ec28c061ed7d1ec7b86e6e6a2))
* **core:** support percent encoding ([8c69f11](https://github.com/developmentseed/multistore/commit/8c69f118ac71bf088e305d9c9e5db825dc303dcc))
* create multistore-cf-workers crate with reusable Workers adapters ([73c79b5](https://github.com/developmentseed/multistore/commit/73c79b582d88334fb7a65970905aaa6bda4b3f57))
* create multistore-path-mapping crate for hierarchical path routing ([19d6626](https://github.com/developmentseed/multistore/commit/19d66268b8d038eae403f51ebb9ca869f4d194ae))
* get-object ([#4](https://github.com/developmentseed/multistore/issues/4)) ([9f3d8e8](https://github.com/developmentseed/multistore/commit/9f3d8e85ce97a265907e4473401b94829258c992))
* support pagination on bucket list ([017f22d](https://github.com/developmentseed/multistore/commit/017f22d531d6a54e90f2d560fe46b2b1aebce6ea))
* support range requests ([4053c5f](https://github.com/developmentseed/multistore/commit/4053c5f8ae6cf5089c863018ac575ba2caba8e25))
* **workers:** add rate-limiting ([47a5973](https://github.com/developmentseed/multistore/commit/47a5973856f8a4c46167951ce439fe2abf65be59))


### Bug Fixes

* add default allowed roles ([35dd823](https://github.com/developmentseed/multistore/commit/35dd82352e7f14fb8f87c71e98862f737cb96a07))
* apply ListRewrite.add_prefix to Prefix element and fix double-slash in rewrite_key ([3ba9890](https://github.com/developmentseed/multistore/commit/3ba98907a0eea206741afe85c4c042281630709e))
* **ci:** add --cwd to wrangler commands and fix step reference ([a250cf2](https://github.com/developmentseed/multistore/commit/a250cf2efd0ae0d32a36132c935fec9b1fcce5bf))
* **ci:** let wrangler output stream directly ([f98780e](https://github.com/developmentseed/multistore/commit/f98780e55380086dae3e2e3ec83bfa34187a0c11))
* **ci:** pass CLOUDFLARE_ACCOUNT_ID as secret to reusable workflow ([c2ff2a7](https://github.com/developmentseed/multistore/commit/c2ff2a7b70b304e4b99c3b41aa3b45d0332a12bc))
* correct endpoint ([0d9fd27](https://github.com/developmentseed/multistore/commit/0d9fd27a9f3e55055a1a3723f55a528e9e974cce))
* correct STS endpoint ([3f6b2be](https://github.com/developmentseed/multistore/commit/3f6b2be6f868957fd6d2b19536ae43a2aae6a990))
* ensure cloudflare streams data properly ([19053b2](https://github.com/developmentseed/multistore/commit/19053b29ecc41896f05bd062713f36927289d57d))
* handle Azure and GCS URLs in UnsignedUrlSigner ([3af3845](https://github.com/developmentseed/multistore/commit/3af3845c900843e073dca031a8f15bbe692a1089))
* match S3 ListObjectsV2 delimiter behavior ([ad0acfb](https://github.com/developmentseed/multistore/commit/ad0acfbe953f1ca9dc57c9f2a5b53844143e969f))
* pin worker version ([2752efb](https://github.com/developmentseed/multistore/commit/2752efb7e6cea5b74a6f399e4e025b525f4124dd))
* **rate-limit:** ensure middleware runs before bucket resolution ([b15cd64](https://github.com/developmentseed/multistore/commit/b15cd64664e195c6ed39e3cc8673c62dcd7d4f25))
* support range HEAD requests ([758c44c](https://github.com/developmentseed/multistore/commit/758c44c13cc59a9f9ee6381b3d6b0573fa084c55))
* **workers:** support multipart downloads ([7e4c313](https://github.com/developmentseed/multistore/commit/7e4c313e693d02c4b9adfaa36c82f3851504c41c))
* **workers:** us sqlite durable object storage ([65b7101](https://github.com/developmentseed/multistore/commit/65b71017691d868037815ca8f284bddc6e1c80d8))


### Performance Improvements

* use Cow&lt;BucketConfig&gt; in OidcBackendAuth to avoid per-request clones ([4dff450](https://github.com/developmentseed/multistore/commit/4dff4509a87524ce5eb3d3154de6dfa8c39b9256))
