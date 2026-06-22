import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from opensurity.manifest import AgentManifest


class LocalRegistry:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path.home() / ".opensurity" / "registry.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    trust_level TEXT NOT NULL,
                    trust_score REAL DEFAULT 0.5,
                    endpoint TEXT,
                    registered_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS capabilities (
                    agent_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    description TEXT,
                    PRIMARY KEY (agent_id, capability_id),
                    FOREIGN KEY (agent_id) REFERENCES agents(id)
                );

                CREATE TABLE IF NOT EXISTS used_nonces (
                    nonce TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL
                );
            """)

    def register(self, manifest: AgentManifest) -> None:
        """Upserts an agent manifest into the registry."""
        manifest.validate()
        now = datetime.utcnow().isoformat() + "Z"
        manifest_json = json.dumps(manifest.to_dict())

        with self._get_conn() as conn:
            # Check if exists to preserve trust_score and registered_at
            row = conn.execute("SELECT trust_score, registered_at FROM agents WHERE id = ?", (manifest.id,)).fetchone()
            
            if row:
                trust_score = row["trust_score"]
                registered_at = row["registered_at"]
            else:
                trust_score = 0.5
                registered_at = now

            conn.execute("""
                INSERT OR REPLACE INTO agents 
                (id, name, version, manifest_json, trust_level, trust_score, endpoint, registered_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                manifest.id,
                manifest.name,
                manifest.version,
                manifest_json,
                manifest.trust.level,
                trust_score,
                manifest.trust.endpoint,
                registered_at,
                now
            ))

            # Replace capabilities
            conn.execute("DELETE FROM capabilities WHERE agent_id = ?", (manifest.id,))
            for cap in manifest.capabilities:
                conn.execute("""
                    INSERT INTO capabilities (agent_id, capability_id, description)
                    VALUES (?, ?, ?)
                """, (manifest.id, cap.id, cap.description))

    def discover(self, capability_id: str) -> List[AgentManifest]:
        """Returns all agents that declare this capability, ordered by trust score (descending)."""
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT a.manifest_json 
                FROM agents a
                JOIN capabilities c ON a.id = c.agent_id
                WHERE c.capability_id = ?
                ORDER BY a.trust_score DESC
            """, (capability_id,)).fetchall()

            return [AgentManifest.from_dict(json.loads(row["manifest_json"])) for row in rows]

    def get(self, agent_id: str) -> Optional[AgentManifest]:
        """Returns manifest by agent ID."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT manifest_json FROM agents WHERE id = ?", (agent_id,)).fetchone()
            if row:
                return AgentManifest.from_dict(json.loads(row["manifest_json"]))
            return None

    def list_all(self) -> List[AgentManifest]:
        """Returns all agents."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT manifest_json FROM agents ORDER BY name").fetchall()
            return [AgentManifest.from_dict(json.loads(row["manifest_json"])) for row in rows]

    def update_trust_score(self, agent_id: str, score: float) -> None:
        """Updates the trust score for an agent."""
        now = datetime.utcnow().isoformat() + "Z"
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE agents 
                SET trust_score = ?, updated_at = ?
                WHERE id = ?
            """, (score, now, agent_id))

    def check_and_store_nonce(self, nonce: str, ttl_seconds: int = 300) -> bool:
        """
        Checks if a nonce has been used. If not, stores it with a TTL.
        Returns True if the nonce is fresh and valid.
        Returns False if it's a replay.
        """
        now = time.time()
        expires_at = now + ttl_seconds
        
        with self._get_conn() as conn:
            # Cleanup expired nonces (best effort)
            conn.execute("DELETE FROM used_nonces WHERE expires_at < ?", (now,))
            
            try:
                conn.execute("INSERT INTO used_nonces (nonce, expires_at) VALUES (?, ?)", (nonce, expires_at))
                return True
            except sqlite3.IntegrityError:
                # Nonce already exists
                return False
