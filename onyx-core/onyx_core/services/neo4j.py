import structlog
from neo4j import GraphDatabase, Driver
from typing import Optional
import os

from onyx_core import graph_queries as gq

logger = structlog.get_logger(__name__)

class Neo4jService:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "")
        self._driver: Optional[Driver] = None

    def connect(self):
        if not self._driver:
            try:
                self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
                self._driver.verify_connectivity()
                logger.info("Neo4j connected successfully", uri=self.uri)
            except Exception as e:
                logger.error("Failed to connect to Neo4j", error=str(e))
                self._driver = None

    def close(self):
        if self._driver:
            self._driver.close()
            logger.info("Neo4j connection closed")

    def get_session(self):
        if not self._driver:
            self.connect()
        if self._driver:
            return self._driver.session()
        raise Exception("Neo4j driver is not initialized")

    # ---- graph operations (queries are built and validated in onyx_core.graph_queries) ----

    def _run(self, query: str, **params):
        with self.get_session() as session:
            return [r.data() for r in session.run(query, **params)]

    def upsert_entity(self, label: str, entity_id: str, props: dict | None = None):
        return self._run(gq.upsert_entity(label), id=entity_id, props=props or {})

    def link(self, src_label: str, src_id: str, rel: str, dst_label: str, dst_id: str, props: dict | None = None):
        return self._run(gq.upsert_relationship(src_label, rel, dst_label), src=src_id, dst=dst_id, props=props or {})

    def attack_chain(self, indicator_value: str, depth: int = 4):
        return self._run(gq.attack_chain(depth), value=indicator_value)

    def neighbors(self, entity_id: str, limit: int = 50):
        return self._run(gq.neighbors(), id=entity_id, limit=max(1, min(int(limit), 500)))


neo4j_service = Neo4jService()
