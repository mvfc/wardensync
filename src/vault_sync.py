import logging
import hashlib
import json
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from bw_client import BitwardenClient

logger = logging.getLogger(__name__)

SYNC_FIELD = "sync_id"
IGNORED_FIELDS = {"id", "revisionDate", "creationDate", "deletedDate", "organizationId", SYNC_FIELD}
VOLATILE_LOGIN_KEYS = {"passwordRevisionDate", "totp"}

class SyncPlanner:
    def __init__(self, source_client: BitwardenClient, destination_client: BitwardenClient, max_workers: int = 8):
        """
        :param source_client: BitwardenClient for source vault (e.g., bw-src)
        :param destination_client: BitwardenClient for destination vault (e.g., bw-dest)
        """
        self.source = source_client
        self.dest = destination_client
        self.max_workers = max_workers

    # -------------------------------------------------
    # Sync ID helpers
    # -------------------------------------------------
    @staticmethod
    def compute_sync_id(item: dict) -> str:
        """Deterministic hash of name + username + first URI domain"""
        name = (item.get("name") or "").strip().lower()
        username = (item.get("login", {}).get("username") or "").strip().lower()
        uris = item.get("login", {}).get("uris") or []
        domain = ""
        if uris:
            uri = uris[0].get("uri", "").strip().lower()
            domain = uri.split("//")[-1].split("/")[0]
        return hashlib.sha256(f"{name}|{username}|{domain}".encode("utf-8")).hexdigest()

    @staticmethod
    def get_sync_id(item: dict) -> str:
        from bw_client import BitwardenClient
        return BitwardenClient.get_custom_field(item, SYNC_FIELD)

    @staticmethod
    def set_sync_id(item: dict, sync_id: str) -> dict:
        from bw_client import BitwardenClient
        return BitwardenClient.set_custom_field(item, SYNC_FIELD, sync_id)

    @staticmethod
    def build_key(item: dict) -> str:
        """Used for fuzzy matching when sync_id is missing."""
        name = (item.get("name") or "").strip().lower()
        uri = ""
        uris = item.get("login", {}).get("uris") or []
        if uris:
            uri = uris[0].get("uri", "").strip().lower()
        return f"{name}|{uri}"

    # -------------------------------------------------
    # Comparison logic
    # -------------------------------------------------
    def _normalize_item(self, item: dict) -> dict:
        """Return a deeply normalized version of an item for stable but precise comparison."""
        clean = copy.deepcopy(item)

        # Drop ignored top-level keys
        for k in list(clean.keys()):
            if k in IGNORED_FIELDS:
                clean.pop(k, None)

        # --- Normalize login
        login = clean.get("login")
        if isinstance(login, dict):
            for k in list(login.keys()):
                if k in VOLATILE_LOGIN_KEYS:
                    login.pop(k, None)
            # Normalize URIs deterministically
            uris = login.get("uris")
            if isinstance(uris, list):
                norm_uris = []
                for u in uris:
                    if not isinstance(u, dict):
                        continue
                    normalized_uri = {
                        "uri": (u.get("uri") or "").strip().lower(),
                        "match": u.get("match", 0),  # default match=0 if missing
                        "port": u.get("port", None),
                    }
                    norm_uris.append(normalized_uri)
                # Sort deterministically by URI and then by match
                login["uris"] = sorted(norm_uris, key=lambda x: (x["uri"], x.get("match", 0)))
            clean["login"] = login

        # --- Normalize custom fields
        fields = clean.get("fields")
        if isinstance(fields, list):
            filtered = [f for f in fields if f.get("name") != SYNC_FIELD]
            for f in filtered:
                if "value" in f and f["value"] is None:
                    f["value"] = ""
            clean["fields"] = sorted(filtered, key=lambda f: f.get("name", ""))

        # --- Normalize notes and text
        if clean.get("notes") is None:
            clean["notes"] = ""

        # --- Normalize all None values deeply
        def normalize_values(obj):
            if isinstance(obj, dict):
                return {k: normalize_values(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [normalize_values(v) for v in obj]
            elif obj is None:
                return ""
            return obj

        clean = normalize_values(clean)
        return clean

    def _items_differ(self, src: dict, dst: dict) -> bool:
        src_norm = self._normalize_item(src)
        dst_norm = self._normalize_item(dst)

        src_json = json.dumps(src_norm, sort_keys=True, separators=(",", ":"))
        dst_json = json.dumps(dst_norm, sort_keys=True, separators=(",", ":"))

        if src_json != dst_json:
            logger.debug(f"🧩 Difference detected for {src.get('name')}")
            logger.debug(f"SRC: {src_json}")
            logger.debug(f"DST: {dst_json}")
            return True
        return False

    # -------------------------------------------------
    # Fuzzy matching (parallel)
    # -------------------------------------------------
    def _match_unmatched(
        self, src_unmatched: list[dict], dst_unmatched: list[dict]
    ) -> tuple[list[tuple[dict, dict]], list[dict]]:
        """Parallel fuzzy match: returns (update_pairs, create_list)."""
        dst_lookup = {self.build_key(d): d for d in dst_unmatched}
        update_pairs = []
        create_list = []

        def match_one(src):
            key = self.build_key(src)
            dst = dst_lookup.get(key)
            if dst:
                return ("update", src, dst)
            else:
                return ("create", src, None)

        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(match_one, s) for s in src_unmatched]
            for f in as_completed(futures):
                results.append(f.result())

        for action, src, dst in results:
            if action == "update" and dst:
                update_pairs.append((src, dst))
                if dst in dst_unmatched:
                    dst_unmatched.remove(dst)
            elif action == "create":
                create_list.append(src)

        return update_pairs, create_list

    # -------------------------------------------------
    # Main planning logic
    # -------------------------------------------------
    def plan(self) -> tuple[list[dict], list[tuple[dict, dict]], list[dict]]:
        """
        Compute the sync plan:
          - to_create: source items that must be created in destination
          - to_update: (src, dst) pairs that must be updated
          - to_delete: destination items missing from source
        """
        logger.info("📥 Fetching source and destination items...")
        src_items = self.source.list_items()
        dst_items = self.dest.list_items()

        # Maps and unmatched lists
        src_map, dst_map = {}, {}
        src_unmatched, dst_unmatched = [], []

        for s in src_items:
            sid = self.get_sync_id(s) or self.compute_sync_id(s)
            self.set_sync_id(s, sid)
            if sid:
                src_map[sid] = s
            else:
                src_unmatched.append(s)

        for d in dst_items:
            sid = self.get_sync_id(d) or self.compute_sync_id(d)
            if sid:
                dst_map[sid] = d
            else:
                dst_unmatched.append(d)

        to_create: list[dict] = []
        to_update: list[tuple[dict, dict]] = []
        to_delete: list[dict] = []

        # 1. Match by sync_id
        logger.info("🔍 Matching by sync_id...")
        matched_pairs = []
        for sid, src in src_map.items():
            dst = dst_map.get(sid)
            if dst:
                matched_pairs.append((src, dst))
            else:
                to_create.append(src)

        # Parallel compare matched pairs
        logger.info("🧮 Comparing matched items (parallel)...")
        def compare_pair(pair):
            src_item, dst_item = pair
            diff = self._items_differ(src_item, dst_item)
            return (src_item, dst_item, diff)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(compare_pair, p) for p in matched_pairs]
            for f in as_completed(futures):
                src_item, dst_item, diff = f.result()
                if diff:
                    to_update.append((src_item, dst_item))

        # 2. Identify deletions (missing in source)
        for sid, dst in dst_map.items():
            if sid not in src_map:
                to_delete.append(dst)

        # 3. Fuzzy match for items without sync_id
        logger.info("🧩 Running fuzzy match for unmatched items...")
        fuzzy_updates, fuzzy_creates = self._match_unmatched(src_unmatched, dst_unmatched)

        # Filter fuzzy updates by diff
        logger.info("🧮 Comparing fuzzy matched items (parallel)...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(compare_pair, p) for p in fuzzy_updates]
            for f in as_completed(futures):
                src_item, dst_item, diff = f.result()
                if diff:
                    to_update.append((src_item, dst_item))

        # Remaining dst_unmatched = deletions
        to_delete.extend(dst_unmatched)
        to_create.extend(fuzzy_creates)

        logger.info(
            f"✅ Plan complete — Create: {len(to_create)}, Update: {len(to_update)}, Delete: {len(to_delete)}"
        )

        return to_create, to_update, to_delete
