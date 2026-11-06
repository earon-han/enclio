#!/bin/sh
set -eu
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 - "$task_root" <<'PY'
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile

root = Path(sys.argv[1])
if platform.system() != "Linux":
    raise SystemExit("package: build and package on Linux, not macOS")
architectures = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
architecture = architectures.get(platform.machine())
if architecture is None:
    raise SystemExit("package: only native Linux arm64 and amd64 builds are supported")
binary = root / "build/tegum"
if not binary.is_file() or binary.is_symlink():
    raise SystemExit("package: run make all first")
elf_header = binary.read_bytes()[:64]
if elf_header[:6] != b"\x7fELF\x02\x01" or len(elf_header) != 64:
    raise SystemExit("package: build/tegum is not a Linux ELF binary")
expected_machine = {"arm64": 183, "amd64": 62}[architecture]
if struct.unpack_from("<H", elf_header, 18)[0] != expected_machine:
    raise SystemExit("package: ELF architecture does not match the native Linux host")
version_match = re.search(r'#define TG_VERSION "([0-9A-Za-z.+-]+)"',
                          (root / "src/tegum.h").read_text())
if not version_match:
    raise SystemExit("package: cannot read TG_VERSION")
version = version_match.group(1)
reported = subprocess.check_output([str(binary), "version"], text=True).strip()
if reported != "tegum " + version:
    raise SystemExit("package: binary version does not match source header; rebuild")
for path in [root / "Makefile", *list((root / "src").glob("*.c")),
             *list((root / "src").glob("*.h"))]:
    if path.stat().st_mtime_ns > binary.stat().st_mtime_ns:
        raise SystemExit("package: source newer than binary; run make all")

def identity():
    return json.loads(subprocess.check_output(
        [sys.executable, str(root / "scripts/source-id.py"), "--json"], text=True))

def output(command):
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=10, check=False)
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return str(error)

information = identity()
epoch_text = os.environ.get("SOURCE_DATE_EPOCH")
if epoch_text is None:
    try:
        epoch_text = subprocess.check_output(
            ["git", "-C", str(root), "show", "-s", "--format=%ct", "HEAD"],
            text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        epoch_text = "0"
try:
    epoch = int(epoch_text)
    if not 0 <= epoch <= 0xffffffff:
        raise ValueError()
except ValueError:
    raise SystemExit("package: SOURCE_DATE_EPOCH must be an unsigned 32-bit integer")

name = f"tegum-{version}-linux-{architecture}"
dist = root / "dist"
dist.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix="tegum-package-", dir=dist) as temporary:
    stage = Path(temporary) / name
    (stage / "bin").mkdir(parents=True)
    shutil.copyfile(binary, stage / "bin/tegum")
    (stage / "bin/tegum").chmod(0o755)
    for relative in ["README.md", "LICENSE", "CHANGELOG.md", "packaging/README.md"]:
        source = root / relative
        if not source.is_file() or source.is_symlink():
            raise SystemExit(f"package: missing required document: {relative}")
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for directory in ["docs", "examples"]:
        for source in sorted((root / directory).rglob("*")):
            # Installation evidence contains the archive's own checksum. Keep
            # raw reports in the repository rather than creating a hash cycle.
            if source.relative_to(root).parts[:2] in {("docs", "evidence"), ("docs", "reports")}:
                continue
            if source.is_symlink():
                raise SystemExit(f"package: symlink in delivery documents: {source.relative_to(root)}")
            if source.is_file() and "__pycache__" not in source.parts and source.suffix != ".pyc":
                target = stage / source.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
    binary_digest = hashlib.sha256((stage / "bin/tegum").read_bytes()).hexdigest()
    manifest = {
        "manifest_schema": 1,
        "name": "tegum", "version": version, "architecture": architecture,
        "platform": "Linux", "delivery": "dynamically-linked ELF",
        "binary_sha256": binary_digest,
        **information,
        "archive_epoch": epoch,
        "runtime_dependencies": {
            "bubblewrap": "/usr/bin/bwrap; installed separately",
            "glibc": "distribution runtime, including ELF loader",
            "libseccomp": "libseccomp.so.2; installed separately",
            "kernel_and_security_policy": "see docs/dependencies.md; run bin/tegum doctor",
        },
        "build_environment": {
            "kernel": platform.release(),
            "dynamic_libraries": re.sub(r"\b0x[0-9a-fA-F]+\b", "<ASLR>", output(["ldd", str(binary)])),
            "bubblewrap_version": output(["/usr/bin/bwrap", "--version"]),
        },
    }
    (stage / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False,
                                                    sort_keys=True, indent=2) + "\n")
    sums = []
    for path in sorted(stage.rglob("*")):
        if path.is_file():
            relative = path.relative_to(stage).as_posix()
            if "\n" in relative or "\r" in relative or "\\" in relative:
                raise SystemExit("package: unsupported delivery filename")
            sums.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + relative)
    (stage / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    archive = Path(temporary) / (name + ".tar.gz")
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path in [stage, *sorted(stage.rglob("*"))]:
                    info = tar.gettarinfo(str(path), arcname=path.relative_to(stage.parent).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    info.pax_headers = {}
                    info.mode = 0o755 if path.is_dir() or path == stage / "bin/tegum" else 0o644
                    if path.is_file():
                        with path.open("rb") as contents:
                            tar.addfile(info, contents)
                    else:
                        tar.addfile(info)
    if identity()["source_tree_sha256"] != information["source_tree_sha256"]:
        raise SystemExit("package: source changed while packaging; retry when edits have finished")
    os.replace(archive, dist / archive.name)

# Include all architectures already present without retaining obsolete checksums.
checksums = []
for archive in sorted(dist.glob("tegum-*.tar.gz")):
    checksums.append(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name)
checksum_file = dist / ".SHA256SUMS.tmp"
checksum_file.write_text("\n".join(checksums) + "\n")
os.replace(checksum_file, dist / "SHA256SUMS")
print(dist / (name + ".tar.gz"))
print("source_tree_sha256=" + information["source_tree_sha256"])
print("binary_sha256=" + binary_digest)
PY
