


# ---------- Database Module ----------
class Database:
    def __init__(self):
        self.entries = {}
        self.groups = {}

    def ensure_grouped_schema(self):
        if "entries" not in self.__dict__ or not self.entries:
            # Migrate older format if needed
            old_entries = self.entries.copy()
            self.entries = old_entries
            self.groups = {}
        for eid, rec in self.entries.items():
            if "group" not in rec or not rec["group"]:
                rec["group"] = "Ungrouped"
        if "Ungrouped" not in self.groups:
            self.groups["Ungrouped"] = {"parent": "", "meta": {}}

    def to_dict(self) -> dict:
        return {"entries": self.entries, "groups": self.groups}

    @classmethod
    def from_dict(cls, data: dict) -> 'Database':
        db = cls()
        db.entries = data.get("entries", {})
        db.groups = data.get("groups", {})
        db.ensure_grouped_schema()
        return db

    def list_groups(self):
        return sorted(self.groups.keys())

    def entries_in_group(self, group_path: str, recursive=True):
        if recursive:
            return {eid: rec for eid, rec in self.entries.items()
                    if rec.get("group", "").startswith(group_path)}
        else:
            return {eid: rec for eid, rec in self.entries.items()
                    if rec.get("group", "") == group_path}

    def create_group(self, group_path: str) -> bool:
        if group_path in self.groups:
            return False
        # Auto-create parents
        parts = group_path.split("/")
        for i in range(1, len(parts) + 1):
            p = "/".join(parts[:i])
            if p not in self.groups:
                parent = "/".join(parts[:i-1]) if i > 1 else ""
                self.groups[p] = {"parent": parent, "meta": {}}
        return True

    def rename_group(self, old_path: str, new_path: str) -> bool:
        if old_path not in self.groups:
            return False
        if new_path in self.groups:
            return False  # Prevent conflicts
        if not new_path.strip():
            return False  # Prevent empty names

        # Update the group dict
        self.groups[new_path] = self.groups.pop(old_path)

        # Update subgroups and their parents
        for g in list(self.groups.keys()):
            if g.startswith(old_path + "/"):
                new_g = g.replace(old_path, new_path, 1)
                self.groups[new_g] = self.groups.pop(g)
                # Update parent: if it's a direct child, parent is new_path; otherwise, reconstruct
                parts = new_g.split("/")
                self.groups[new_g]["parent"] = "/".join(parts[:-1]) if len(parts) > 1 else ""

        # Update entries
        for eid, rec in self.entries.items():
            if rec["group"] == old_path or rec["group"].startswith(old_path + "/"):
                rec["group"] = rec["group"].replace(old_path, new_path, 1)

        return True

    def delete_group(self, group_path: str, reassign_to="Ungrouped") -> bool:
        if group_path not in self.groups:
            return False
        # Reassign entries in this group and children
        for eid, rec in self.entries.items():
            if rec.get("group", "") == group_path or rec.get("group", "").startswith(group_path + "/"):
                rec["group"] = reassign_to
        # Remove child groups recursively
        to_delete = [g for g in self.groups if g == group_path or g.startswith(group_path + "/")]
        for g in to_delete:
            self.groups.pop(g, None)
        # Ensure reassign_to exists
        self.create_group(reassign_to)
        return True

    def assign_entry_to_group(self, eid: str, group_path: str) -> bool:
        if eid not in self.entries:
            return False
        self.create_group(group_path)
        self.entries[eid]["group"] = group_path
        return True