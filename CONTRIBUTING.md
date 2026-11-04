# Contributing

Contributions are welcome via pull requests on GitHub.

## Workflow

1. Fork the repository and create a branch from `master`.
2. Install dependencies: `composer install`.
3. Make your change and cover it with tests.
4. Run the full quality gate locally:

   ```bash
   composer ci   # pint --test, phpstan (level 8), pest
   ```

5. Open a pull request describing the motivation and the change.

## Guidelines

- Follow the PER coding style (`composer format` fixes it automatically).
- Every PHP file declares `strict_types=1`.
- Public API changes must be reflected in `README.md` and `CHANGELOG.md`.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).
