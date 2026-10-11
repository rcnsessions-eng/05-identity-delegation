FROM zero-trust-constrained-tools-mcp:0.1.0 AS runtime
COPY 05-identity-delegation/code/app/identity /app/app/identity
COPY 05-identity-delegation/code/scripts /identity-scripts
CMD ["uvicorn", "app.identity.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM zero-trust-constrained-tools-checks:0.1.0 AS checks
COPY 05-identity-delegation/code/app/identity /app/app/identity
COPY 05-identity-delegation/code/tests /identity-tests
COPY 05-identity-delegation/code/scripts /identity-scripts
COPY 05-identity-delegation/code/pyproject.toml /identity/pyproject.toml
CMD ["sh", "-c", "ruff check --config /identity/pyproject.toml /app/app/identity /identity-tests /identity-scripts && ruff format --check --config /identity/pyproject.toml /app/app/identity /identity-tests /identity-scripts && mypy --config-file /identity/pyproject.toml /app/app/identity && python -m pytest -p no:cacheprovider /identity-tests -q && python -m pytest -p no:cacheprovider --import-mode=importlib /mcp-tests /isolation-tests /checks /app/tests -q && opa test /policy /tools-policy -v && python /scripts/mutation_check.py"]