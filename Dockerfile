# Multi-stage build → small runtime image.
#
# cargo-chef splits dependency compilation from app compilation so CI layer
# caching actually works: a src-only change rebuilds the app, not the world.
FROM rust:1-slim AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# The SvelteKit SPA (CRYPTARCH-129), built to static files the binary embeds.
# It is the whole UI: its CSS, fonts and favicon are part of the build.
FROM node:24-slim AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
# Full copy (governed by .dockerignore): the binary embeds migrations/ and
# frontend/build at compile time (sqlx::migrate!, rust-embed) — an image
# built without them doesn't compile at all.
COPY . .
# The real frontend build, replacing build.rs's placeholder (frontend/build is
# in .dockerignore, so nothing local can be embedded by accident).
COPY --from=frontend /frontend/build frontend/build
RUN cargo build --release

FROM debian:trixie-slim
# postgresql-client-18 comes from PGDG, not Debian main (trixie ships 17), and
# pg_dump refuses to dump a server newer than itself — an 18 client is the
# floor for backing up 16/17/18 managed servers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt trixie-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-18 \
    && apt-get purge -y curl gnupg && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/cryptarch /usr/local/bin/cryptarch
WORKDIR /
EXPOSE 8080
ENTRYPOINT ["cryptarch"]
