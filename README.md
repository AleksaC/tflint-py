# tflint-py

[![Add new versions](https://github.com/AleksaC/tflint-py/actions/workflows/add-new-versions.yml/badge.svg)](https://github.com/AleksaC/tflint-py/actions/workflows/add-new-versions.yml)
[![Run tests](https://github.com/AleksaC/tflint-py/actions/workflows/tests.yml/badge.svg)](https://github.com/AleksaC/tflint-py/actions/workflows/tests.yml)

pip installable [tflint](https://github.com/terraform-linters/tflint) binary with wrapper for pre-commit.

The mechanism by which the tflint binary is downloaded is adapted from
[shellcheck-py](https://github.com/shellcheck-py/shellcheck-py).

## Getting started

### Installation

This package was built to make it more convenient to run tflint as a pre-commit
hook, so it hasn't been published to PyPI. However you can install it using git:

```shell script
pip install git+https://github.com/AleksaC/tflint-py.git@v0.9.1
```

### pre-commit hook

To use the pre-commit hook include the following config in your `.pre-commit-config.yaml` file:

```yaml
repos:
  - repo: https://github.com/AleksaC/tflint-py
    rev: v0.9.1
    hooks:
      - id: tflint
```

## Contact 🙋‍♂️
- [Personal website](https://aleksac.me)
- <a target="_blank" href="http://twitter.com/aleksa_c_"><img alt='Twitter followers' src="https://img.shields.io/twitter/follow/aleksa_c_.svg?style=social"></a>
- aleksacukovic1@gmail.com
