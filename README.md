# Preparation before test

```shell
(cd factory-v1 && cargo near build non-reproducible-wasm)
(cd v1 && cargo near build non-reproducible-wasm)
(cd v2 && cargo near build non-reproducible-wasm)

(cd e2e-test && cp .env.sample .env && nano .env)
```

# How to run test

```shell
cargo test
(cd e2e-test && npm run test)
```
