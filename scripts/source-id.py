#!/usr/bin/env python3
"""Reproducible identity for source files, including uncommitted new files."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess


EXCLUDED_DIRECTORIES = {
    ".git", "build", "dist", "__pycache__", ".venv", "venv",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache", "htmlcov",
}
EXCLUDED_FILES = {".DS_Store", ".coverage"}
SOURCE_ROOTS = ("src", "tests", "scripts", "examples", ".github/workflows", "Makefile", "Dockerfile")


def source_files(root):
    """Yield ordinary files and symlinks; never traverse a symlink directory."""
    def visit(directory):
        for path in sorted(directory.iterdir(), key=lambda p: os.fsencode(p.name)):
            relative = path.relative_to(root).as_posix()
            if (path.name in EXCLUDED_DIRECTORIES or path.name in EXCLUDED_FILES
                    or path.suffix == ".pyc"):
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                yield path
            elif stat.S_ISDIR(mode):
                yield from visit(path)
            elif stat.S_ISREG(mode):
                yield path
            else:
                raise ValueError(f"unsupported source file type: {relative}")
    for relative in SOURCE_ROOTS:
        path = root / relative
        if path.is_symlink() or path.is_file():
            yield path
        elif path.is_dir():
            yield from visit(path)


def git_output(root, *arguments):
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *arguments], stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return None


def source_info(root):
    digest = hashlib.sha256(b"tegum-source-tree-v1\0")
    count = 0
    for path in sorted(source_files(root),
                       key=lambda p: os.fsencode(p.relative_to(root).as_posix())):
        mode = path.lstat().st_mode
        name = os.fsencode(path.relative_to(root).as_posix())
        if stat.S_ISLNK(mode):
            kind = b"L"
            contents = os.fsencode(os.readlink(path))
        else:
            kind = b"X" if mode & 0o111 else b"F"
            contents = path.read_bytes()
        # Length framing makes names/newlines and arbitrary contents unambiguous.
        digest.update(kind + struct.pack(">Q", len(name)) + name)
        digest.update(struct.pack(">Q", len(contents)) + contents)
        count += 1
    head = git_output(root, "rev-parse", "HEAD")
    status = git_output(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    return {
        "source_id_schema": 1,
        "source_tree_sha256": digest.hexdigest(),
        "source_file_count": count,
        "source_scope": list(SOURCE_ROOTS),
        "git_head": head.decode("ascii").strip() if head else None,
        # Git status is intentionally the full worktree status, while the tree
        # identity covers only the explicitly listed build/validation inputs.
        "git_dirty": bool(status) if status is not None else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="include Git metadata")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    arguments = parser.parse_args()
    information = source_info(arguments.root.resolve())
    print(json.dumps(information, ensure_ascii=False, sort_keys=True) if arguments.json
          else information["source_tree_sha256"])


if __name__ == "__main__":
    main()
