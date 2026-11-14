"""Knowledge base — vector store for security guidance and repair patterns."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("secureheal.knowledge")

# Pre-built knowledge entries for the 8 target CWEs
CWE_KNOWLEDGE: list[dict] = [
    {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "description": "Improper neutralization of special elements used in an SQL command.",
        "repair_patterns": {
            "python": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "java": "Use PreparedStatement: ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); ps.setString(1, userId);",
        },
        "guidance": "Never concatenate user input into SQL strings. Always use parameterized queries or an ORM.",
    },
    {
        "cwe_id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "description": "Improper neutralization of input during web page generation.",
        "repair_patterns": {
            "python": "Use html.escape() or framework auto-escaping: from html import escape; safe = escape(user_input)",
            "java": "Use OWASP Java Encoder: Encode.forHtml(userInput) or use Thymeleaf's auto-escaping",
        },
        "guidance": "Encode all user-supplied data before rendering in HTML. Use Content-Security-Policy headers.",
    },
    {
        "cwe_id": "CWE-862",
        "name": "Missing Authorization",
        "description": "The product does not perform an authorization check when an actor attempts to access a resource.",
        "repair_patterns": {
            "python": "Add dependency injection for auth: async def endpoint(current_user: User = Depends(get_current_user))",
            "java": "Add @PreAuthorize or check SecurityContextHolder: Authentication auth = SecurityContextHolder.getContext().getAuthentication();",
        },
        "guidance": "Every endpoint accessing protected resources must verify the caller's authorization.",
    },
    {
        "cwe_id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The server can be induced to make requests to unintended destinations.",
        "repair_patterns": {
            "python": "Validate URLs against allowlist: from urllib.parse import urlparse; parsed = urlparse(url); if parsed.hostname not in ALLOWED_HOSTS: raise ValueError",
            "java": "Validate URL and block private IPs: URL url = new URL(input); InetAddress addr = InetAddress.getByName(url.getHost()); if (addr.isSiteLocalAddress()) throw new SecurityException();",
        },
        "guidance": "Whitelist allowed destinations. Block requests to private IP ranges and localhost.",
    },
    {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "description": "Improper limitation of a pathname to a restricted directory.",
        "repair_patterns": {
            "python": "Canonicalize and validate: safe = Path(base_dir).joinpath(filename).resolve(); if not str(safe).startswith(str(Path(base_dir).resolve())): raise ValueError",
            "java": "Use Path.normalize: Path resolved = basePath.resolve(userInput).normalize(); if (!resolved.startsWith(basePath)) throw new SecurityException();",
        },
        "guidance": "Always resolve and canonicalize paths. Verify the result stays within the allowed directory.",
    },
    {
        "cwe_id": "CWE-78",
        "name": "OS Command Injection",
        "description": "Improper neutralization of special elements used in an OS command.",
        "repair_patterns": {
            "python": "Use subprocess with list args: subprocess.run(['ls', '-l', safe_path], shell=False, check=True)",
            "java": "Use ProcessBuilder with list args: new ProcessBuilder(\"ls\", \"-l\", safePath).start();",
        },
        "guidance": "Never pass user input to shell commands. Use safe APIs with argument lists instead of shell=True.",
    },
    {
        "cwe_id": "CWE-502",
        "name": "Insecure Deserialization",
        "description": "Deserializing untrusted data can result in arbitrary code execution.",
        "repair_patterns": {
            "python": "Replace pickle with JSON: import json; data = json.loads(user_input)  # Never: pickle.loads(user_input)",
            "java": "Use JSON instead of ObjectInputStream: ObjectMapper mapper = new ObjectMapper(); MyClass obj = mapper.readValue(input, MyClass.class);",
        },
        "guidance": "Never deserialize untrusted data with pickle, shelve, or Java ObjectInputStream. Use JSON or validated schemas.",
    },
    {
        "cwe_id": "CWE-798",
        "name": "Hardcoded Credentials",
        "description": "The product contains hard-coded credentials such as passwords or cryptographic keys.",
        "repair_patterns": {
            "python": "Use environment variables: import os; db_password = os.environ['DB_PASSWORD']",
            "java": "Use environment variables: String dbPassword = System.getenv(\"DB_PASSWORD\");",
        },
        "guidance": "Store credentials in environment variables or secret managers. Never commit secrets to source code.",
    },
]


class KnowledgeBase:
    """Vector-store-backed knowledge base for security guidance and repair patterns."""

    def __init__(self) -> None:
        self._collection = None
        self._client = None

    def initialize(self, persist_directory: str = "./chroma_data") -> None:
        """Create or load the ChromaDB collection."""
        try:
            import chromadb

            self._client = chromadb.PersistentClient(path=persist_directory)
            self._collection = self._client.get_or_create_collection(
                name="secureheal_knowledge",
                metadata={"hnsw:space": "cosine"},
            )

            # Pre-populate if empty
            if self._collection.count() == 0:
                self._populate_cwe_knowledge()

            logger.info(
                "Knowledge base initialized with %d documents at %s",
                self._collection.count(),
                persist_directory,
            )
        except ImportError:
            logger.warning("ChromaDB not available — knowledge base running in fallback mode")
        except Exception as exc:
            logger.warning("Failed to initialize ChromaDB: %s — using fallback", exc)

    def _populate_cwe_knowledge(self) -> None:
        """Pre-populate with knowledge for the 8 target CWEs."""
        if not self._collection:
            return

        documents = []
        metadatas = []
        ids = []

        for entry in CWE_KNOWLEDGE:
            doc = (
                f"CWE: {entry['cwe_id']} - {entry['name']}\n"
                f"Description: {entry['description']}\n"
                f"Python repair pattern: {entry['repair_patterns'].get('python', 'N/A')}\n"
                f"Java repair pattern: {entry['repair_patterns'].get('java', 'N/A')}\n"
                f"Guidance: {entry['guidance']}"
            )
            documents.append(doc)
            metadatas.append({"cwe_id": entry["cwe_id"], "name": entry["name"]})
            ids.append(entry["cwe_id"])

        self._collection.add(documents=documents, metadatas=metadatas, ids=ids)
        logger.info("Pre-populated %d CWE knowledge entries", len(documents))

    def add_security_knowledge(self, documents: list[dict]) -> None:
        """Embed and store additional security knowledge documents."""
        if not self._collection:
            logger.warning("Knowledge base not initialized")
            return

        doc_texts = [d.get("content", "") for d in documents]
        doc_metas = [d.get("metadata", {}) for d in documents]
        doc_ids = [d.get("id", f"doc_{i}") for i, d in enumerate(documents)]

        self._collection.add(documents=doc_texts, metadatas=doc_metas, ids=doc_ids)

    def query_repair_patterns(
        self, vulnerability_type: str, language: str, k: int = 5
    ) -> list[dict]:
        """Retrieve relevant repair patterns for a vulnerability type and language."""
        if self._collection:
            results = self._collection.query(
                query_texts=[f"{vulnerability_type} repair pattern {language}"],
                n_results=min(k, self._collection.count()),
            )
            return [
                {"document": doc, "metadata": meta}
                for doc, meta in zip(
                    results.get("documents", [[]])[0],
                    results.get("metadatas", [[]])[0],
                )
            ]

        # Fallback: direct lookup
        return [
            {
                "document": f"{e['cwe_id']}: {e['repair_patterns'].get(language, '')}",
                "metadata": {"cwe_id": e["cwe_id"]},
            }
            for e in CWE_KNOWLEDGE
            if vulnerability_type.lower() in e["name"].lower()
            or vulnerability_type.upper() in e["cwe_id"]
        ]

    def query_security_guidance(self, cwe_id: str) -> list[dict]:
        """Get guidance for a specific CWE identifier."""
        if self._collection:
            results = self._collection.query(
                query_texts=[f"Security guidance for {cwe_id}"],
                n_results=3,
                where={"cwe_id": cwe_id} if cwe_id.startswith("CWE-") else None,
            )
            return [
                {"document": doc, "metadata": meta}
                for doc, meta in zip(
                    results.get("documents", [[]])[0],
                    results.get("metadatas", [[]])[0],
                )
            ]

        # Fallback
        return [
            {"document": e["guidance"], "metadata": {"cwe_id": e["cwe_id"]}}
            for e in CWE_KNOWLEDGE
            if e["cwe_id"] == cwe_id
        ]
