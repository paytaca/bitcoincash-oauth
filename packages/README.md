# Bitcoin Cash OAuth Server Packages

This directory contains reusable, pip-installable packages for integrating Bitcoin Cash OAuth authentication into your server applications.

## Packages

### `bitcoincash-oauth-fastapi`

FastAPI integration with automatic OAuth endpoints and dependency injection.

```bash
cd bitcoincash-oauth-fastapi
pip install -e .
```

See [README.md](bitcoincash-oauth-fastapi/README.md) for usage.

### `bitcoincash-oauth-django`

Django and Django REST Framework (DRF) integration with views and permission classes.

```bash
cd bitcoincash-oauth-django
pip install -e .
```

See [README.md](bitcoincash-oauth-django/README.md) for usage.

## Publishing to PyPI

### Build and Publish FastAPI Package

```bash
cd bitcoincash-oauth-fastapi
python -m pip install build twine
python -m build
python -m twine upload dist/*
```

### Build and Publish Django Package

```bash
cd bitcoincash-oauth-django
python -m pip install build twine
python -m build
python -m twine upload dist/*
```

## Development

Install both packages in development mode:

```bash
pip install -e packages/bitcoincash-oauth-fastapi
pip install -e packages/bitcoincash-oauth-django
```

## Package Structure

Both packages follow the same structure:

```
bitcoincash-oauth-{framework}/
├── bitcoincash_oauth_{framework}/    # Main package
│   ├── __init__.py                    # Exports and integration
│   ├── validator.py                   # ECDSA & CashAddr validation
│   ├── token_manager.py              # OAuth token management
│   ├── views.py                       # Django views (Django only)
│   └── drf.py                         # DRF integration (Django only)
├── pyproject.toml                     # Package configuration
└── README.md                          # Usage documentation
```

## Why Separate Packages?

The packages are kept separate because:

1. **Dependencies**: Each has different framework dependencies (FastAPI vs Django)
2. **Installation Size**: Users only install what they need
3. **Versioning**: Can version and release independently
4. **Maintenance**: Easier to maintain and test separately

If you prefer a single package, you could create a `bitcoincash-oauth-core` with shared validator/token code, then have thin wrapper packages for each framework. However, for simplicity, we currently duplicate the core code (it's small enough).
