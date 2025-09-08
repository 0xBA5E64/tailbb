# syntax=docker/dockerfile:1.7-labs
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY --exclude=".db-data" ./ ./

RUN cargo build --release

FROM alpine 
WORKDIR /app
COPY --from=builder /build/target/release/tailbb /app
COPY --from=builder /build/templates /app/templates
COPY --from=builder /build/static /app/static
EXPOSE 3000/tcp
EXPOSE 3000/udp
CMD ["./tailbb"]