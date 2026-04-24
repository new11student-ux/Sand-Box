# Contributing Guide

We welcome contributions to the Advanced Cybersecurity Sandbox Platform!

## Getting Started
1. Fork the repository.
2. Clone your fork locally.
3. Install dependencies: `pip install -r requirements.txt`
4. Set up pre-commit hooks (if applicable).

## Code Style
- We follow PEP 8 for Python code.
- Ensure all new features are accompanied by tests in the `tests/` directory.
- Document any new APIs or ML features.

## Submitting a Pull Request
1. Create a new branch: `git checkout -b feature/my-new-feature`
2. Commit your changes: `git commit -m 'Add some feature'`
3. Push to the branch: `git push origin feature/my-new-feature`
4. Open a Pull Request against the `main` branch.

All PRs require review and must pass the GitHub Actions CI pipeline (Trivy scans & PyTest) before merging.
