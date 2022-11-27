import os
from glob import glob

from tflint_py._main import get_config
from tflint_py._main import get_dirs
from tflint_py._main import lint
from tflint_py._main import main


def test_get_dirs():
    files = glob("testing/**/*.tf", recursive=True)
    dirs = get_dirs(files)

    expected_dirs = {
        os.path.join("testing", "valid"),
        os.path.join("testing", "nested", "invalid"),
    }

    assert len(dirs) == len(expected_dirs) and all(dir in expected_dirs for dir in dirs)


def test_get_dirs_root(monkeypatch):
    monkeypatch.chdir(os.path.join("testing", "valid"))

    files = glob("*.tf", recursive=True)
    dirs = get_dirs(files)

    assert dirs == {"."}


def test_get_config_no_config(monkeypatch):
    monkeypatch.chdir(os.path.join("testing", "valid"))

    config = get_config(".")

    assert config is None


def test_get_config_nested():
    for path in [
        os.path.join("testing", "nested", "invalid"),
        os.path.join("testing", "nested"),
    ]:
        assert get_config(path) == os.path.abspath("testing/nested/.tflint.hcl")


def test_lint_valid():
    return_code = lint("testing/valid")

    assert return_code == 0


def test_lint_invalid():
    return_code = lint("testing/nested/invalid")

    assert return_code != 0


def test_cli():
    files = glob("testing/**/*.tf", recursive=True)

    assert main(files) != 0
