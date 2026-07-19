# Multi-stage build → small runtime image.
#
# cargo-chef splits dependency compilation from app compilation so CI layer
# caching actually works: a src-only change rebuilds the app, not the world.
FROM rust:1-slim AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
# Full copy (governed by .dockerignore): the binary embeds migrations/ AND
# assets/ at compile time (sqlx::migrate! + include_str!) — an image built
# without assets/ doesn't compile at all.
COPY . .
RUN cargo build --release

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/cryptarch /usr/local/bin/cryptarch
WORKDIR /
EXPOSE 8080
ENTRYPOINT ["cryptarch"]
