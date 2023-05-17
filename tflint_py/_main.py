from __future__ import annotations

import argparse
import os
import subprocess

from typing import List
from typing import Optional
from typing import Set


initialized = set()


def get_dirs(filenames: List[str]) -> Set[str]:
    dirs = set(map(lambda filename: os.path.dirname(filename), filenames))

    if "" in dirs:
        dirs.remove("")
        dirs.add(".")

    return dirs


def get_config(dir: str) -> Optional[str]:
    conf_dir = os.path.abspath(dir)
    while os.path.dirname(conf_dir) != conf_dir:
        conf_path = os.path.join(conf_dir, ".tflint.hcl")
        if os.path.exists(conf_path):
            return conf_path
        conf_dir = os.path.dirname(conf_dir)


def run_tflint_command(
    *, options: Optional[List[str]] = None, dir: Optional[str] = None, **kwargs
) -> int:
    command = ["tflint"]
    if options is not None:
        command.extend(options)
    if dir is not None:
        command.extend(["--chdir", dir])

    res = subprocess.run(command, **kwargs)

    return res.returncode


def init(dir):
    conf_path = get_config(dir)
    if conf_path and conf_path not in initialized:
        run_tflint_command(options=["--init", f"--config={conf_path}"])
        initialized.add(conf_path)


def lint(dir: str) -> int:
    init(dir)
    return run_tflint_command(dir=dir)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*")
    args = parser.parse_args(argv)

    status_code = 0
    for dir in get_dirs(args.filenames):
        status_code |= lint(dir)

    return status_code
