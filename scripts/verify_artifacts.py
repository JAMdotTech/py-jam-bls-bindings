"""Check distributable contents, stable ABI tags, and publishable metadata."""
import hashlib
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path


def main():
    artifacts = sorted(Path(sys.argv[1]).glob("*"))
    artifacts = [p for p in artifacts if p.suffix == ".whl" or p.name.endswith(".tar.gz")]
    assert artifacts, "No distribution artifacts supplied"
    for path in artifacts:
        if path.suffix == ".whl":
            assert "-cp312-abi3-" in path.name, path.name
            assert "none-any" not in path.name, path.name
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                assert "jam_bls/__init__.py" in names
                assert any(p.startswith("jam_bls/_native.") and p.endswith(".so") for p in names)
                metadata_name = next(p for p in names if p.endswith(".dist-info/METADATA"))
                metadata = BytesParser().parsebytes(archive.read(metadata_name))
                assert metadata["Name"] == "py-jam-bls-bindings"
                assert metadata["Version"] == "0.1.0"
                assert metadata["Requires-Python"] == ">=3.12"
                assert metadata["License-Expression"] == "GPL-3.0-only"
                for dependency in metadata.get_all("Requires-Dist", []):
                    assert 'extra == "test"' in dependency, dependency
        else:
            with tarfile.open(path) as archive:
                names = {p.partition("/")[2] for p in archive.getnames()}
                for required in ("Cargo.toml", "Cargo.lock", "rust/src/lib.rs", "pyproject.toml",
                                 "setup.cfg", "LICENSE", "LICENSES/PyJAMaz-Apache-2.0.txt",
                                 "PROVENANCE.md", "README.md", "src/jam_bls/__init__.py",
                                 "tests/test_bls.py", "scripts/cross_verify.py"):
                    assert required in names, required
                assert not any(p.startswith("target/") or p.endswith(".so") for p in names)
        print(hashlib.sha256(path.read_bytes()).hexdigest(), path.name)


if __name__ == "__main__":
    main()
