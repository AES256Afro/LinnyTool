"""Backup and restore manager.

Creates timestamped backups of configuration files before hardening,
with a JSON manifest tracking original metadata and SHA256 hashes.
Supports granular single-file restore or full rollback.
"""

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from core import __version__, logger


BACKUP_ROOT = Path("/var/lib/linnytool/backups")


@dataclass
class BackupEntry:
    original_path: str
    backup_path: str
    sha256: str
    uid: int
    gid: int
    mode: str       # octal string like "0644"
    size: int


@dataclass
class BackupManifest:
    timestamp: str
    reason: str
    linnytool_version: str
    distro: str
    files: list[BackupEntry] = field(default_factory=list)


def create_backup(
    files: list[str | Path],
    reason: str = "manual",
    distro_name: str = "",
    backup_root: Path = BACKUP_ROOT,
) -> Optional[Path]:
    """Create a timestamped backup of the given files.

    Args:
        files: List of absolute file paths to back up.
        reason: Why this backup was created (e.g., "pre-hardening-basic").
        distro_name: Distro display name for the manifest.
        backup_root: Root directory for backups.

    Returns:
        Path to the backup directory, or None if no files were backed up.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = backup_root / timestamp
    _ensure_dir(backup_dir)

    manifest = BackupManifest(
        timestamp=timestamp,
        reason=reason,
        linnytool_version=__version__,
        distro=distro_name,
    )

    backed_up = 0
    for filepath in files:
        filepath = Path(filepath)
        if not filepath.exists():
            logger.debug("Skipping non-existent file: %s", filepath)
            continue
        if not filepath.is_file():
            logger.debug("Skipping non-file: %s", filepath)
            continue

        try:
            entry = _backup_single_file(filepath, backup_dir)
            manifest.files.append(entry)
            backed_up += 1
        except (PermissionError, OSError) as e:
            logger.error("Failed to backup %s: %s", filepath, e)

    if backed_up == 0:
        # Clean up empty backup dir
        try:
            backup_dir.rmdir()
        except OSError:
            pass
        logger.info("No files to backup")
        return None

    # Write manifest
    manifest_path = backup_dir / "manifest.json"
    manifest_data = {
        "timestamp": manifest.timestamp,
        "reason": manifest.reason,
        "linnytool_version": manifest.linnytool_version,
        "distro": manifest.distro,
        "files": [
            {
                "original_path": e.original_path,
                "backup_path": e.backup_path,
                "sha256": e.sha256,
                "uid": e.uid,
                "gid": e.gid,
                "mode": e.mode,
                "size": e.size,
            }
            for e in manifest.files
        ],
    }
    manifest_path.write_text(json.dumps(manifest_data, indent=2))
    logger.info("Backup created: %s (%d files, reason: %s)", backup_dir, backed_up, reason)
    return backup_dir


def restore_file(backup_dir: Path, original_path: str) -> bool:
    """Restore a single file from a backup snapshot.

    Args:
        backup_dir: Path to the backup snapshot directory.
        original_path: The original absolute path of the file to restore.

    Returns:
        True if the file was restored successfully.
    """
    manifest = _load_manifest(backup_dir)
    if manifest is None:
        logger.error("No manifest found in %s", backup_dir)
        return False

    for entry in manifest["files"]:
        if entry["original_path"] == original_path:
            backup_file = Path(entry["backup_path"])
            if not backup_file.exists():
                logger.error("Backup file missing: %s", backup_file)
                return False

            # Verify integrity
            current_hash = _compute_sha256(backup_file)
            if current_hash != entry["sha256"]:
                logger.error("Backup integrity check failed for %s", backup_file)
                return False

            # Restore
            target = Path(original_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(backup_file), str(target))
            os.chown(str(target), entry["uid"], entry["gid"])
            os.chmod(str(target), int(entry["mode"], 8))

            logger.info("Restored: %s", original_path)
            return True

    logger.error("File not found in backup manifest: %s", original_path)
    return False


def restore_all(backup_dir: Path) -> list[str]:
    """Full rollback from a backup snapshot.

    Returns:
        List of successfully restored file paths.
    """
    manifest = _load_manifest(backup_dir)
    if manifest is None:
        logger.error("No manifest found in %s", backup_dir)
        return []

    restored = []
    for entry in manifest["files"]:
        if restore_file(backup_dir, entry["original_path"]):
            restored.append(entry["original_path"])
        else:
            logger.error("Failed to restore: %s", entry["original_path"])

    logger.info("Restored %d/%d files from %s",
                len(restored), len(manifest["files"]), backup_dir)
    return restored


def list_snapshots(backup_root: Path = BACKUP_ROOT) -> list[dict]:
    """List all available backup snapshots.

    Returns:
        List of dicts with: path, timestamp, reason, file_count, total_size_kb.
    """
    if not backup_root.exists():
        return []

    snapshots = []
    for entry in sorted(backup_root.iterdir(), reverse=True):
        if not entry.is_dir():
            continue
        manifest = _load_manifest(entry)
        if manifest is None:
            continue

        total_size = sum(f.get("size", 0) for f in manifest.get("files", []))
        snapshots.append({
            "path": str(entry),
            "timestamp": manifest.get("timestamp", entry.name),
            "reason": manifest.get("reason", "unknown"),
            "file_count": len(manifest.get("files", [])),
            "total_size_kb": round(total_size / 1024, 1),
            "distro": manifest.get("distro", ""),
        })

    return snapshots


def get_latest_snapshot(backup_root: Path = BACKUP_ROOT) -> Optional[Path]:
    """Return path to the most recent backup snapshot."""
    if not backup_root.exists():
        return None
    dirs = sorted(
        [d for d in backup_root.iterdir() if d.is_dir() and (d / "manifest.json").exists()],
        reverse=True,
    )
    return dirs[0] if dirs else None


def _backup_single_file(filepath: Path, backup_dir: Path) -> BackupEntry:
    """Back up a single file preserving directory structure."""
    # Mirror the directory structure inside the backup
    relative = str(filepath).lstrip("/")
    dest = backup_dir / relative
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Copy with metadata preservation
    shutil.copy2(str(filepath), str(dest))

    # Get original metadata
    stat = filepath.stat()

    return BackupEntry(
        original_path=str(filepath),
        backup_path=str(dest),
        sha256=_compute_sha256(filepath),
        uid=stat.st_uid,
        gid=stat.st_gid,
        mode=oct(stat.st_mode & 0o7777),
        size=stat.st_size,
    )


def _load_manifest(backup_dir: Path) -> Optional[dict]:
    """Load and parse manifest.json from a backup directory."""
    manifest_path = backup_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, PermissionError) as e:
        logger.error("Failed to read manifest: %s: %s", manifest_path, e)
        return None


def _compute_sha256(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _ensure_dir(path: Path) -> None:
    """Create directory with restrictive permissions."""
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(path), 0o700)
    except PermissionError:
        pass
