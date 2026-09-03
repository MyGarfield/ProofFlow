"""Install a downloaded receipt without overwrite or symlink races."""

from __future__ import annotations

import argparse
import os
import stat
import sys
from contextlib import suppress
from pathlib import Path

MAX_RECEIPT_BYTES = 2 * 1024 * 1024


def _reject_symlinked_parent(path: Path) -> None:
    current = path.parent
    while True:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("receipt parent is not a real directory")
        if current.parent == current:
            return
        current = current.parent


def install(source: Path, destination: Path) -> None:
    _reject_symlinked_parent(destination)
    source_stat = source.stat()
    if not stat.S_ISREG(source_stat.st_mode) or source.is_symlink():
        raise ValueError("receipt source is not a regular file")
    if source_stat.st_size > MAX_RECEIPT_BYTES:
        raise ValueError("receipt exceeds output limit")
    temporary = destination.parent / f".{destination.name}.proofflow-tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as target, source.open("rb") as payload:
            while chunk := payload.read(64 * 1024):
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        # link() is atomic and refuses to overwrite an existing destination;
        # follow_symlinks=False keeps a pre-existing symlink fail-closed.
        os.link(temporary, destination, follow_symlinks=False)
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        install(args.source, args.destination)
    except Exception as error:
        print("RECEIPT_INSTALL_FAILED", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
