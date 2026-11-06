ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libseccomp-dev bubblewrap ca-certificates curl python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/tegum
COPY . .
RUN make clean && make && chown -R 1000:1000 /opt/tegum
USER 1000:1000
CMD ["python3", "tests/integration.py", "--network", "--output", "/tmp/integration.json"]
