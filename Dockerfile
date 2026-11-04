# Stdio MCP proxy. Supply an operator-managed config and audit key; no demo or
# credentials are embedded. See docs/glama-container.md before starting.
FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/Aethelgard-Systems/lookfirst"
LABEL org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 HOME=/home/lookfirst
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY lookfirst ./lookfirst
RUN python -m pip install --no-cache-dir . \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin lookfirst \
    && mkdir -p /config /state \
    && chown lookfirst:lookfirst /state \
    && chmod 700 /state
USER lookfirst
ENTRYPOINT ["lookfirst"]
CMD ["serve", "--config", "/config/lookfirst.yaml", "--transport", "stdio"]
