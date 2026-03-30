"""
Profile Manager — CRUD, import/export, and multi-profile application.

Profile schema (JSON):
{
  "name": "Logon/Logoff Activity",
  "description": "...",
  "version": "1.0",
  "author": "EventHawk",
  "tags": ["authentication"],
  "event_ids": [4624, 4625, 4634],
  "sources": ["Security"],
  "target_logs": ["Security.evtx"],
  "keywords": [],
  "severity_overrides": {"4625": "warning"}
}

Default profiles: evtx_tool/profiles/defaults/*.json
User profiles: ./profiles/*.json (relative to cwd) or custom dir
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Iterator

from evtx_tool.core._json_compat import fast_loads, fast_dumps

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────

_HERE = Path(__file__).parent
DEFAULTS_DIR = _HERE / "defaults"
DEFAULT_USER_DIR = Path("profiles")


class ProfileManager:
    """
    Manages DFIR profiles: load, save, create, delete, import, export.

    Parameters
    ----------
    user_dir : str | Path
        Directory for user-created profiles. Defaults to ./profiles/
    """

    def __init__(self, user_dir: str | Path | None = None):
        self._user_dir = Path(user_dir) if user_dir else DEFAULT_USER_DIR
        self._user_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict] = {}
        self._load_all()

    # ── Loading ────────────────────────────────────────────────────────────────

    def _load_all(self) -> None:
        """Load all profiles from defaults dir and user dir."""
        self._cache.clear()
        # Defaults first (lower priority)
        if DEFAULTS_DIR.exists():
            for path in sorted(DEFAULTS_DIR.glob("*.json")):
                try:
                    profile = self._load_file(path)
                    self._cache[profile["name"]] = profile
                except Exception as exc:
                    logger.warning("Failed to load default profile %s: %s", path.name, exc)

        # User profiles override defaults with same name
        for path in sorted(self._user_dir.glob("*.json")):
            try:
                profile = self._load_file(path)
                self._cache[profile["name"]] = profile
                profile["_user_defined"] = True
            except Exception as exc:
                logger.warning("Failed to load user profile %s: %s", path.name, exc)

        logger.info("Loaded %d profiles (%d defaults, %d user)",
                    len(self._cache),
                    sum(1 for p in self._cache.values() if not p.get("_user_defined")),
                    sum(1 for p in self._cache.values() if p.get("_user_defined")))

    def _load_file(self, path: Path) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            profile = fast_loads(f.read())
        profile["_source_path"] = str(path)
        return self._validate_profile(profile)

    def reload(self) -> None:
        """Reload all profiles from disk."""
        self._load_all()

    # ── Validation ─────────────────────────────────────────────────────────────

    @staticmethod
    def _validate_profile(profile: dict) -> dict:
        """Ensure required fields exist with correct types."""
        required = {
            "name": str,
            "description": str,
            "event_ids": list,
            "sources": list,
        }
        for field, typ in required.items():
            if field not in profile:
                if typ is list:
                    profile[field] = []
                elif typ is str:
                    profile[field] = ""
            elif not isinstance(profile[field], typ):
                profile[field] = typ(profile[field]) if typ is str else []

        # Normalize event_ids to int
        # BUG 20 fix: also handle float values (e.g. 4624.0 from JSON quirks)
        # and numeric strings; skip only values that truly cannot be converted.
        normalized_ids = []
        for e in profile["event_ids"]:
            if isinstance(e, (int, float)):
                normalized_ids.append(int(e))
            elif isinstance(e, str) and e.strip().rstrip(".0").isdigit():
                try:
                    normalized_ids.append(int(float(e)))
                except (ValueError, TypeError):
                    pass
        profile["event_ids"] = normalized_ids

        # Ensure optional fields
        profile.setdefault("version", "1.0")
        profile.setdefault("author", "")
        profile.setdefault("tags", [])
        profile.setdefault("target_logs", [])
        profile.setdefault("keywords", [])
        profile.setdefault("severity_overrides", {})
        profile.setdefault("correlation_rules", [])
        # Extended filter fields (user-customisable)
        profile.setdefault("channels", [])
        profile.setdefault("computers", [])
        profile.setdefault("users", [])
        profile.setdefault("levels", [])
        profile.setdefault("conditions", [])
        profile.setdefault("case_sensitive", False)

        return profile

    # ── CRUD ───────────────────────────────────────────────────────────────────

    def list_profiles(self) -> list[dict]:
        """Return all profiles sorted by name."""
        return sorted(self._cache.values(), key=lambda p: p["name"])

    def list_names(self) -> list[str]:
        return sorted(self._cache.keys())

    def get(self, name: str) -> dict | None:
        return self._cache.get(name)

    def get_by_partial_name(self, partial: str) -> list[dict]:
        """Find profiles whose name contains partial (case-insensitive)."""
        pl = partial.lower()
        return [p for n, p in self._cache.items() if pl in n.lower()]

    def create(self, profile: dict) -> dict:
        """Create a new user profile. Raises ValueError if name taken."""
        profile = self._validate_profile(profile)
        name = profile["name"]
        if name in self._cache:
            raise ValueError(f"Profile '{name}' already exists. Use update() to modify it.")
        filepath = self._user_dir / self._name_to_filename(name)
        self._save_file(profile, filepath)
        profile["_source_path"] = str(filepath)
        profile["_user_defined"] = True
        self._cache[name] = profile
        logger.info("Created profile: %s", name)
        return profile

    def update(self, name: str, updates: dict) -> dict:
        """Update an existing profile. Saves to user dir (never overwrites defaults)."""
        existing = self._cache.get(name)
        if existing is None:
            raise KeyError(f"Profile '{name}' not found.")
        merged = {**existing, **updates}
        merged["name"] = name  # name is immutable
        merged = self._validate_profile(merged)
        filepath = self._user_dir / self._name_to_filename(name)
        self._save_file(merged, filepath)
        merged["_source_path"] = str(filepath)
        merged["_user_defined"] = True
        self._cache[name] = merged
        logger.info("Updated profile: %s", name)
        return merged

    def delete(self, name: str) -> bool:
        """Delete a user profile. Returns False if it's a default (not deletable)."""
        profile = self._cache.get(name)
        if profile is None:
            return False
        if not profile.get("_user_defined"):
            logger.warning("Cannot delete built-in profile: %s", name)
            return False
        path = Path(profile.get("_source_path", ""))
        if path.exists():
            path.unlink()
        del self._cache[name]
        logger.info("Deleted profile: %s", name)
        return True

    # ── Import / Export ─────────────────────────────────────────────────────────

    def export_profile(self, name: str, dest_path: str) -> None:
        """Export a profile to a JSON file."""
        profile = self._cache.get(name)
        if profile is None:
            raise KeyError(f"Profile '{name}' not found.")
        export_profile = {k: v for k, v in profile.items() if not k.startswith("_")}
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(fast_dumps(export_profile, indent=2))
        logger.info("Exported profile '%s' → %s", name, dest_path)

    def import_profile(self, src_path: str, overwrite: bool = False) -> dict:
        """Import a profile from a JSON file. Saves to user dir."""
        path = Path(src_path)
        if not path.exists():
            raise FileNotFoundError(f"Profile file not found: {src_path}")
        profile = self._load_file(path)
        name = profile["name"]
        if name in self._cache and not overwrite:
            raise ValueError(f"Profile '{name}' already exists. Use overwrite=True to replace.")
        dest = self._user_dir / self._name_to_filename(name)
        self._save_file(profile, dest)
        profile["_source_path"] = str(dest)
        profile["_user_defined"] = True
        self._cache[name] = profile
        logger.info("Imported profile '%s' from %s", name, src_path)
        return profile

    def export_all(self, dest_dir: str) -> int:
        """Export all profiles to a directory. Returns number exported."""
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        count = 0
        for name, profile in self._cache.items():
            export_profile = {k: v for k, v in profile.items() if not k.startswith("_")}
            out_path = dest / self._name_to_filename(name)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(fast_dumps(export_profile, indent=2))
            count += 1
        logger.info("Exported %d profiles to %s", count, dest_dir)
        return count

    # ── Filter generation ──────────────────────────────────────────────────────

    def build_filter(self, profile_names: list[str], base_filter: dict | None = None) -> dict:
        """
        Build a combined filter dict for the given profile names.
        Unions all event_ids and sources. base_filter restrictions applied on top.
        """
        from evtx_tool.core.filters import empty_filter, build_combined_filter

        profiles = []
        missing = []
        for name in profile_names:
            p = self._cache.get(name)
            if p is None:
                # Try partial match
                matches = self.get_by_partial_name(name)
                if matches:
                    profiles.append(matches[0])
                else:
                    missing.append(name)
            else:
                profiles.append(p)

        if missing:
            logger.warning("Profiles not found: %s", ", ".join(missing))

        bf = base_filter if base_filter is not None else empty_filter()
        return build_combined_filter(bf, profiles)

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _name_to_filename(name: str) -> str:
        """Convert profile name to a safe filename."""
        safe = "".join(c if c.isalnum() or c in "- _" else "_" for c in name)
        return safe[:80] + ".json"

    @staticmethod
    def _save_file(profile: dict, path: Path) -> None:
        export = {k: v for k, v in profile.items() if not k.startswith("_")}
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(fast_dumps(export, indent=2))

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, name: str) -> bool:
        return name in self._cache
