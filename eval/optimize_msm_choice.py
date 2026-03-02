#!/usr/bin/env python3

import logging
import os
import subprocess as sp
import re
from pathlib import Path


logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _find_project_root():
    self_path = Path(os.path.realpath(__file__))
    root_path = self_path
    while not (root_path / ".git").is_dir():
        if root_path == root_path.parent:
            # top-most directory reached
            logger.error("no project root found")
            return None
        root_path = root_path.parent
    logger.info(f"found project root '{root_path}'")
    return root_path


def _compile_target():
    logger.info(f"compiling target")
    cmd = ["cargo", "build", "--release"]
    logger.info(" ".join(cmd))
    res = sp.run(cmd, capture_output=True)

    if res.returncode != 0:
        logger.error(f"compilation of target failed")
        logger.error(f"stdout: '{res.stdout}'")
        logger.error(f"stderr: '{res.stderr}'")
        return False

    logger.info(f"compilation successful")
    return True


def _run_target(proj_dir, num_msms, msm_size):
    bin_dir = proj_dir / "target" / "release"
    logger.info(f"running target in {bin_dir}")
    cmd = ["./ibe_schemes", str(num_msms), str(msm_size)]
    logger.info(" ".join(cmd))
    res = sp.run(cmd, capture_output=True, cwd=bin_dir, encoding="utf-8")
    
    if res.returncode != 0:
        logger.error(f"running target failed")
        logger.error(f"stdout: '{res.stdout}'")
        logger.error(f"stderr: '{res.stderr}'")
        return None

    logger.info(f"target run successful")
    output = str(res.stdout)
    return _analyse_output(output)


def _analyse_output(str):
    logger.info(f"analysing output")
    # \u00B5 and \u03BC handle two different unicode variants for greek mu (micro seconds)
    regex = r"time:\s+\[\d+\.\d+ (?:ns|\u00B5s|\u03BCs|ms|s) (\d+\.\d+) (ns|\u00B5s|\u03BCs|ms|s) \d+\.\d+ (?:ns|\u00B5s|\u03BCs|ms|s)\]"
    m = re.search(regex, str, re.MULTILINE | re.UNICODE)
    if m is None:
        logger.error(f"unexpected output format")
        logger.error(f"data: '{str}'")
        return None
    time = float(m[1])
    unit = m[2]
    # conversion factors to milliseconds
    factor = {"ns": 1e-6, "\u00B5s": 1e-3, "\u03BCs": 1e-3, "ms": 1e0, "s": 1e3}
    logger.info(f"analysis successful")
    return time * factor[unit]


def _divs(n):
    return [d for d in range(1, n+1) if n % d == 0]


def main():
    project_dir = _find_project_root()
    _compile_target()

    N = 10_080 # has much more divisors than 10_000
    for d in _divs(N):
        num_msms = d
        msm_size = N // d
        res = _run_target(project_dir, num_msms, msm_size)
        print(f"{num_msms} {msm_size}-MSMs take {res:.4f} ms")


if __name__ == "__main__":
    main()