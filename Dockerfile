FROM python:3.13-slim-bookworm
    
RUN apt update && \
    apt install -y --no-install-recommends \
        curl \
        unzip \
    \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -Lo bw.zip "https://bitwarden.com/download/?app=cli&platform=linux"; \
    \
    unzip bw.zip -d /usr/local/bin; \
    \
    chmod +x /usr/local/bin/bw; \
    \
    rm bw.zip

RUN mkdir -p /root/.config/bitwarden-cli-src /root/.config/bitwarden-cli-dest

RUN printf '%s\n' '#!/bin/sh' \
 'export BITWARDENCLI_APPDATA_DIR=/root/.config/bitwarden-cli-src' \
 'exec /usr/local/bin/bw "$@"' \
 > /usr/local/bin/bw-src && chmod +x /usr/local/bin/bw-src

RUN printf '%s\n' '#!/bin/sh' \
 'export BITWARDENCLI_APPDATA_DIR=/root/.config/bitwarden-cli-dest' \
 'exec /usr/local/bin/bw "$@"' \
 > /usr/local/bin/bw-dest && chmod +x /usr/local/bin/bw-dest

ENV PATH="/usr/local/bin:${PATH}"

COPY . /app

WORKDIR /app

CMD ["python", "./src/run.py"]