import json
import re
from pathlib import Path
from functools import lru_cache

DATASET = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "mitre"
    / "enterprise-attack.json"
)


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


@lru_cache(maxsize=1)
def load_attack_data():
    if not DATASET.exists():
        raise FileNotFoundError(f"MITRE dataset not found: {DATASET}")

    bundle = json.loads(DATASET.read_text(encoding='utf-8'))

    objects = {
        obj["id"]: obj
        for obj in bundle.get("objects", [])
        if obj.get("id")
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    }

    relationships = [
        obj for obj in bundle.get("objects", [])
        if obj.get("type") == "relationship"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]

    return objects, relationships


def search_techniques(query: str, platform: str = None, limit: int = 10):
    objects, _ = load_attack_data()
    query = query.strip().lower()

    if not query:
        return {"status": "invalid_query", "results": []}

    matches = []
    max_results = min(max(limit, 1), 25)

    for obj in objects.values():
        if obj.get("type") != "attack-pattern":
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")
        technique_id = external_id(obj)
        platforms = obj.get("x_mitre_platforms", [])

        if platform and platform.lower() not in [
            item.lower() for item in platforms
        ]:
            continue

        name_lower = name.lower()
        id_lower = (technique_id or "").lower()
        description_lower = description.lower()

        if id_lower == query:
            score = 100
            matched_in = "technique_id"
        elif name_lower == query:
            score = 95
            matched_in = "name"
        elif name_lower.startswith(query):
            score = 85
            matched_in = "name"
        elif query in name_lower:
            score = 75
            matched_in = "name"
        elif query in id_lower:
            score = 70
            matched_in = "technique_id"
        elif query in description_lower:
            score = 25
            matched_in = "description"
        else:
            continue

        matches.append((score, {
            "technique_id": technique_id,
            "name": name,
            "description": description[:1200],
            "platforms": platforms,
            "tactics": [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
            ],
            "matched_in": matched_in,
            "url": next(
                (
                    ref.get("url")
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                None,
            ),
        }))

    matches.sort(
        key=lambda item: (-item[0], item[1]["name"].lower())
    )
    results = [item[1] for item in matches[:max_results]]

    return {
        "status": "success",
        "query": query,
        "result_count": len(results),
        "total_matches": len(matches),
        "results": results,
    }


def get_technique(technique_id: str):
    objects, relationships = load_attack_data()
    technique_id = technique_id.strip().upper()

    technique = next(
        (
            obj for obj in objects.values()
            if obj.get("type") == "attack-pattern"
            and external_id(obj) == technique_id
        ),
        None,
    )

    if not technique:
        return {
            "status": "not_found",
            "technique_id": technique_id,
        }

    technique_stix_id = technique["id"]

    def related_objects(rel_type, source=True):
        results = []

        for rel in relationships:
            if rel.get("relationship_type") != rel_type:
                continue

            if source and rel.get("target_ref") != technique_stix_id:
                continue

            if not source and rel.get("source_ref") != technique_stix_id:
                continue

            ref = (
                rel.get("source_ref")
                if source else rel.get("target_ref")
            )

            obj = objects.get(ref)
            if not obj:
                continue

            results.append({
                "id": external_id(obj),
                "name": obj.get("name"),
                "type": obj.get("type"),
                "description": (obj.get("description") or "")[:1000],
            })

        return results

    used_by = related_objects("uses")
    used_by_count = len(used_by)

    return {
        "status": "success",
        "technique_id": technique_id,
        "name": technique.get("name"),
        "description": technique.get("description"),
        "platforms": technique.get("x_mitre_platforms", []),
        "tactics": [
            phase.get("phase_name")
            for phase in technique.get("kill_chain_phases", [])
        ],
        "is_subtechnique": technique.get("x_mitre_is_subtechnique", False),
        "references": [
            ref.get("url")
            for ref in technique.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ],
        "detection_strategies": related_objects("detects"),
        "mitigations": related_objects("mitigates"),
        "used_by": used_by[:10],
        "used_by_total": used_by_count,
        "used_by_truncated": used_by_count > 10,
        "subtechniques": [
            {
                "id": external_id(objects[rel["source_ref"]]),
                "name": objects[rel["source_ref"]].get("name"),
                "type": "attack-pattern",
            }
            for rel in relationships
            if rel.get("relationship_type") == "subtechnique-of"
            and rel.get("target_ref") == technique_stix_id
            and rel.get("source_ref") in objects
        ],
        "parent_techniques": related_objects("subtechnique-of"),
        "source": "MITRE ATT&CK Enterprise STIX dataset",
    }
