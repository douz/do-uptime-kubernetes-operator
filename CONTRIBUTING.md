# Contributing

Thanks for contributing to `do-uptime-kubernetes-operator`.

## Development Setup

1. Clone the repository.
2. Create and activate a Python virtual environment.
3. Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

4. Run tests:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Pull Request Guidelines

1. Keep changes focused and small.
2. Add or update tests when behavior changes.
3. Update `README.md` and Helm chart docs if installation, configuration, or runtime behavior changes.
4. Ensure CI is green before requesting review.

## Commit Messages

Prefer conventional-style messages, for example:

- `feat: add monitor reconciliation guard`
- `fix: handle missing ingress host`
- `docs: clarify helm install options`
- `test: add reconcile unit coverage`

## Reporting Bugs

Please use the bug report issue template and include:

- Kubernetes version
- Operator chart/app version
- Reproduction steps
- Expected vs actual behavior
- Relevant logs/events
