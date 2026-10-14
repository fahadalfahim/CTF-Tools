"""Package only project sources; exclude investigations, credentials and caches."""
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
destination = root / "dist" / "apostrophe-0.1.1.zip"
destination.parent.mkdir(exist_ok=True)
files = [root / name for name in ("README.md", "VALIDATION.md", "pyproject.toml", "Dockerfile", "compose.yaml", ".dockerignore", ".gitignore")]
for folder in ("apostrophe", "flagforge", "tests", "examples", "scripts"):
    files.extend(p for p in (root / folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(files):
        archive.write(path, "apostrophe/" + path.relative_to(root).as_posix())
print(destination)
print("Packaged %d source files; investigation data excluded." % len(files))
