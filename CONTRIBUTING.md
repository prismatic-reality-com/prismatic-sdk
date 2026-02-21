# Contributing to Prismatic SDK

We love your input! We want to make contributing to Prismatic SDK as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## We Develop with GitHub

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## We Use [GitHub Flow](https://guides.github.com/introduction/flow/index.html)

Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any Contributions You Make Will Be Under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report Bugs Using GitHub's [Issues](https://github.com/korczis/prismatic-sdk/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/korczis/prismatic-sdk/issues/new); it's that easy!

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

People *love* thorough bug reports. I'm not even kidding.

## Development Setup

1. Clone the repository
2. Install dependencies: `mix deps.get`
3. Run tests: `mix test`
4. Check code quality: `mix credo --strict`
5. Check types: `mix dialyzer`

## Testing

- Add tests for any new functionality
- Ensure all tests pass with `mix test`
- Run `mix test --cover` to check coverage
- Property-based tests are preferred for complex logic

## Code Style

- Follow the existing code style
- Run `mix format` to automatically format your code
- Use `mix credo --strict` to check for style issues
- Add type specifications (`@spec`) for all public functions
- Document all public functions with `@doc`

## License

By contributing, you agree that your contributions will be licensed under its MIT License.

## References

This document was adapted from the open-source contribution guidelines for [Facebook's Draft](https://github.com/facebook/draft-js/blob/a9316a723f9e918afde44dea68b5f9f39b7d9b00/CONTRIBUTING.md)