# ---------- build / runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        luajit libluajit-5.1-dev luarocks \
        gcc make pkg-config \
        libssl-dev libsecp256k1-dev \
        lua-cjson lua-socket \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN luarocks make lunarblock-scm-1.rockspec

VOLUME /data
EXPOSE 48351 48341

ENTRYPOINT ["luajit", "src/main.lua"]
CMD ["--datadir=/data", "--network=mainnet"]
