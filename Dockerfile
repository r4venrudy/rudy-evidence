FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN python3 tests/verify_vendor.py \
    && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build build --parallel 2 \
    && ctest --test-dir build --output-on-failure \
    && DESTDIR=/package cmake --install build

FROM debian:bookworm-slim
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/r4venrudy/rudy-evidence" \
      org.opencontainers.image.description="Offline security findings CLI and native SDK: normalize, redact, merge, compare and export SARIF." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${VCS_REF}"
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /package/usr/local/ /usr/local/
COPY examples/*.json /usr/local/share/rudy-evidence/examples/
RUN ldconfig && mkdir /data && chown 10001:10001 /data
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["rudy-evidence"]
CMD ["normalize", "native", "example:container", "/usr/local/share/rudy-evidence/examples/native.json"]
