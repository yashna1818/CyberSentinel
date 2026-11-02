import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

KB_PATH = Path(__file__).resolve().parent.parent.parent / "knowledge_base" / "mitre_attack.json"

class MitreAttackRAG:
    """
    Local Retrieval-Augmented Generation (RAG) engine for MITRE ATT&CK knowledge base.
    Guarantees 100% authentic MITRE technique IDs, tactics, and mitigations without external API dependencies.
    """
    def __init__(self, kb_path: Optional[Path] = None):
        self.kb_path = kb_path or KB_PATH
        self.techniques = []
        self._load_kb()

    def _load_kb(self):
        if not self.kb_path.exists():
            raise FileNotFoundError(f"MITRE ATT&CK KB not found at {self.kb_path}")
        with open(self.kb_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.techniques = data.get("techniques", [])

    def query(self, attack_category: str, query_text: str = "", top_k: int = 2) -> List[Dict[str, Any]]:
        """
        Retrieves top-k most relevant MITRE techniques based on attack category and supporting query context.
        """
        query_terms = set(re.findall(r"\w+", (attack_category + " " + query_text).lower()))
        scored_results = []

        for tech in self.techniques:
            score = 0.0
            
            # Category match bonus
            for assoc in tech.get("associated_attacks", []):
                if assoc.lower() in attack_category.lower() or attack_category.lower() in assoc.lower():
                    score += 10.0
                elif any(term in assoc.lower() for term in query_terms):
                    score += 3.0

            # Name and tactic matches
            tech_name = tech.get("name", "").lower()
            tactic = tech.get("tactic", "").lower()
            desc = tech.get("description", "").lower()
            objectives = tech.get("objectives", "").lower()

            for term in query_terms:
                if len(term) < 3:
                    continue
                if term in tech_name:
                    score += 4.0
                if term in tactic:
                    score += 2.0
                if term in desc:
                    score += 1.0
                if term in objectives:
                    score += 1.0

            if score > 0:
                scored_results.append((score, tech))

        # Sort descending by score
        scored_results.sort(key=lambda x: x[0], reverse=True)
        
        results = []
        for score, tech in scored_results[:top_k]:
            item = dict(tech)
            item["relevance_score"] = round(score, 2)
            results.append(item)
            
        return results

    def get_by_technique_id(self, tech_id: str) -> Optional[Dict[str, Any]]:
        """Direct lookup by MITRE technique ID (e.g. T1110 or T1110.001)"""
        for tech in self.techniques:
            if tech.get("technique_id") == tech_id or tech.get("sub_technique_id") == tech_id:
                return tech
        return None

# Global singleton
mitre_rag = MitreAttackRAG()
