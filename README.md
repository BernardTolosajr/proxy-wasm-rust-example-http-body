# Reading http body using proxy-wasm-rust-sdk 

## Build
cargo build --target wasm32-wasi --release

## Run 
docker-compose up

## Test
curl -X POST -H "Content-Type: application/json"  localhost:18000 -d '{"foo":"bar"}' -v
