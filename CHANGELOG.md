# Changelog

## [0.2.0](https://github.com/developmentseed/multistore/compare/multistore-v0.1.0...multistore-v0.2.0) (2026-03-13)


### Features

* add metering middleware ([20395f7](https://github.com/developmentseed/multistore/commit/20395f74def521b4ee74260e8cc8e399e81be25c))
* add metering middleware ([73c2d2c](https://github.com/developmentseed/multistore/commit/73c2d2cdc9dd28606b2da0e4217e222881c05600))
* add OidcDiscoveryRouteHandler for .well-known endpoints ([d5f01a0](https://github.com/developmentseed/multistore/commit/d5f01a0e9b52ce92e9c309f03b48c99adc3ef11a))
* add RouteHandler trait and RequestInfo for pluggable pre-dispatch routing ([1db06a8](https://github.com/developmentseed/multistore/commit/1db06a873b4af645082899520c14439d5b419202))
* add StsRouteHandler for AssumeRoleWithWebIdentity interception ([c6d6d66](https://github.com/developmentseed/multistore/commit/c6d6d66fb908d8471f0e607b1f8ded10b916f30e))
* get-object ([#4](https://github.com/developmentseed/multistore/issues/4)) ([9f3d8e8](https://github.com/developmentseed/multistore/commit/9f3d8e85ce97a265907e4473401b94829258c992))
* support pagination on bucket list ([017f22d](https://github.com/developmentseed/multistore/commit/017f22d531d6a54e90f2d560fe46b2b1aebce6ea))
* support range requests ([4053c5f](https://github.com/developmentseed/multistore/commit/4053c5f8ae6cf5089c863018ac575ba2caba8e25))
* **workers:** add rate-limiting ([47a5973](https://github.com/developmentseed/multistore/commit/47a5973856f8a4c46167951ce439fe2abf65be59))


### Bug Fixes

* add default allowed roles ([35dd823](https://github.com/developmentseed/multistore/commit/35dd82352e7f14fb8f87c71e98862f737cb96a07))
* **ci:** add --cwd to wrangler commands and fix step reference ([a250cf2](https://github.com/developmentseed/multistore/commit/a250cf2efd0ae0d32a36132c935fec9b1fcce5bf))
* **ci:** let wrangler output stream directly ([f98780e](https://github.com/developmentseed/multistore/commit/f98780e55380086dae3e2e3ec83bfa34187a0c11))
* **ci:** pass CLOUDFLARE_ACCOUNT_ID as secret to reusable workflow ([c2ff2a7](https://github.com/developmentseed/multistore/commit/c2ff2a7b70b304e4b99c3b41aa3b45d0332a12bc))
* correct endpoint ([0d9fd27](https://github.com/developmentseed/multistore/commit/0d9fd27a9f3e55055a1a3723f55a528e9e974cce))
* correct STS endpoint ([3f6b2be](https://github.com/developmentseed/multistore/commit/3f6b2be6f868957fd6d2b19536ae43a2aae6a990))
* ensure cloudflare streams data properly ([19053b2](https://github.com/developmentseed/multistore/commit/19053b29ecc41896f05bd062713f36927289d57d))
* pin worker version ([2752efb](https://github.com/developmentseed/multistore/commit/2752efb7e6cea5b74a6f399e4e025b525f4124dd))
* **rate-limit:** ensure middleware runs before bucket resolution ([b15cd64](https://github.com/developmentseed/multistore/commit/b15cd64664e195c6ed39e3cc8673c62dcd7d4f25))
* support range HEAD requests ([758c44c](https://github.com/developmentseed/multistore/commit/758c44c13cc59a9f9ee6381b3d6b0573fa084c55))
* **workers:** support multipart downloads ([7e4c313](https://github.com/developmentseed/multistore/commit/7e4c313e693d02c4b9adfaa36c82f3851504c41c))
* **workers:** us sqlite durable object storage ([65b7101](https://github.com/developmentseed/multistore/commit/65b71017691d868037815ca8f284bddc6e1c80d8))


### Performance Improvements

* use Cow&lt;BucketConfig&gt; in OidcBackendAuth to avoid per-request clones ([4dff450](https://github.com/developmentseed/multistore/commit/4dff4509a87524ce5eb3d3154de6dfa8c39b9256))
