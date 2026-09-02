FROM python:3.12-alpine@sha256:78e98729f8fc4099e53cffb3fe59fd15b18dfa4ace8c914dee0cefa5320068eb

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY deploy/tool-service/requirements.lock /tmp/requirements.lock
RUN python -m pip install \
    --disable-pip-version-check \
    --no-cache-dir \
    --require-hashes \
    --requirement /tmp/requirements.lock \
    && rm /tmp/requirements.lock \
    && python -m pip uninstall --yes pip \
    && python -c "import importlib.util; assert importlib.util.find_spec('pip') is None"

COPY src/ /app/src/
COPY data/rules/ /app/data/rules/
COPY LICENSE NOTICE /usr/share/doc/proofflow/
COPY deploy/tool-service/THIRD_PARTY_NOTICES.md /usr/share/doc/proofflow/

USER 65532:65532
EXPOSE 8787

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/health', timeout=2).read()"]

ENTRYPOINT ["python", "-m", "proofflow.cli", "serve-tools"]
CMD ["--rules", "/app/data/rules/cn_labor_contract_law.catalog.json", "--rules-sha256", "sha256:27686c904451870dd5953ec6e47c155a395b2f279995e50f68aea984e6bf91de", "--host", "0.0.0.0", "--port", "8787"]
