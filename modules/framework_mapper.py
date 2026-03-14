"""
Framework crosswalk mapper for translating controls, evidence, and
assessment results between compliance frameworks.

Builds a bidirectional graph from crosswalk YAML data so that any
framework can be mapped to any other — no framework is treated as
primary. Supports transitive mappings (e.g., SOC2 → NIST → ISO27001).
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, "unmapped": 0}


@dataclass
class MappedControl:
    """A single control mapping result."""
    source_framework: str
    source_control_id: str
    target_framework: str
    target_control_id: str
    confidence: str
    notes: str = ""
    via: list[str] = field(default_factory=list)


class FrameworkMapper:
    """
    Bidirectional crosswalk graph for framework-agnostic control mapping.

    Loads crosswalk data once, builds forward + reverse edges, and
    supports BFS for transitive mappings between any two frameworks.
    """

    def __init__(self, crosswalks: dict | None = None):
        # graph[(framework, control_id)] -> list of (target_fw, target_ctrl, confidence, notes)
        self._graph: dict[tuple[str, str], list[tuple[str, str, str, str]]] = defaultdict(list)
        # track which frameworks we know about
        self._frameworks: set[str] = set()

        if crosswalks:
            self._build_graph(crosswalks)

    @classmethod
    def from_yaml(cls, path: str = "config/crosswalks.yaml") -> FrameworkMapper:
        """Load crosswalk data from a YAML file."""
        crosswalk_path = Path(path)
        if not crosswalk_path.exists():
            logger.warning("Crosswalks file not found: %s", path)
            return cls({})
        with open(crosswalk_path) as f:
            data = yaml.safe_load(f) or {}
        return cls(data.get("crosswalks", {}))

    def _build_graph(self, crosswalks: dict) -> None:
        """Build bidirectional graph from crosswalk definitions."""
        for _key, crosswalk in crosswalks.items():
            source_fw = crosswalk.get("source", "")
            target_fw = crosswalk.get("target", "")
            if not source_fw or not target_fw:
                continue

            self._frameworks.add(source_fw)
            self._frameworks.add(target_fw)

            for source_ctrl, mappings in crosswalk.get("mappings", {}).items():
                for mapping in mappings:
                    target_ctrl = mapping.get("control", "")
                    confidence = mapping.get("confidence", "medium")
                    notes = mapping.get("notes", "")

                    # Forward edge
                    self._graph[(source_fw, source_ctrl)].append(
                        (target_fw, target_ctrl, confidence, notes)
                    )
                    # Reverse edge (confidence downgraded)
                    reverse_confidence = "medium" if confidence == "high" else "low"
                    self._graph[(target_fw, target_ctrl)].append(
                        (source_fw, source_ctrl, reverse_confidence, f"Reverse: {notes}")
                    )

    @property
    def frameworks(self) -> list[str]:
        """List all known frameworks."""
        return sorted(self._frameworks)

    def get_available_mappings(self, framework: str) -> list[str]:
        """Return frameworks reachable from the given framework."""
        reachable: set[str] = set()
        visited: set[tuple[str, str]] = set()
        queue: deque[tuple[str, str]] = deque()

        # Seed with all controls in this framework
        for (fw, ctrl) in self._graph:
            if fw == framework:
                queue.append((fw, ctrl))
                visited.add((fw, ctrl))

        while queue:
            current_fw, current_ctrl = queue.popleft()
            for target_fw, target_ctrl, _conf, _notes in self._graph.get((current_fw, current_ctrl), []):
                reachable.add(target_fw)
                if (target_fw, target_ctrl) not in visited:
                    visited.add((target_fw, target_ctrl))
                    queue.append((target_fw, target_ctrl))

        reachable.discard(framework)
        return sorted(reachable)

    def map_control(
        self,
        source_framework: str,
        control_id: str,
        target_framework: str,
    ) -> list[MappedControl]:
        """
        Map a single control from source to target framework.

        Tries direct mapping first, then BFS for transitive paths.
        Returns empty list if no mapping exists.
        """
        if source_framework == target_framework:
            return [MappedControl(
                source_framework=source_framework,
                source_control_id=control_id,
                target_framework=target_framework,
                target_control_id=control_id,
                confidence="high",
                notes="Identity mapping",
            )]

        # Direct mapping
        direct = self._direct_mappings(source_framework, control_id, target_framework)
        if direct:
            return direct

        # BFS for transitive mapping
        return self._transitive_mapping(source_framework, control_id, target_framework)

    def _direct_mappings(
        self, source_fw: str, control_id: str, target_fw: str
    ) -> list[MappedControl]:
        """Find direct (single-hop) mappings."""
        results = []
        for t_fw, t_ctrl, confidence, notes in self._graph.get((source_fw, control_id), []):
            if t_fw == target_fw:
                results.append(MappedControl(
                    source_framework=source_fw,
                    source_control_id=control_id,
                    target_framework=target_fw,
                    target_control_id=t_ctrl,
                    confidence=confidence,
                    notes=notes,
                ))
        return results

    def _transitive_mapping(
        self, source_fw: str, control_id: str, target_fw: str
    ) -> list[MappedControl]:
        """BFS to find transitive mappings through intermediate frameworks."""
        # Each queue entry: (current_fw, current_ctrl, path_of_frameworks, min_confidence)
        queue: deque[tuple[str, str, list[str], str]] = deque()
        visited: set[tuple[str, str]] = {(source_fw, control_id)}
        results: list[MappedControl] = []

        # Seed from source
        for t_fw, t_ctrl, confidence, _notes in self._graph.get((source_fw, control_id), []):
            if (t_fw, t_ctrl) not in visited:
                visited.add((t_fw, t_ctrl))
                queue.append((t_fw, t_ctrl, [source_fw, t_fw], confidence))

        while queue:
            cur_fw, cur_ctrl, path, path_confidence = queue.popleft()

            if cur_fw == target_fw:
                results.append(MappedControl(
                    source_framework=source_fw,
                    source_control_id=control_id,
                    target_framework=target_fw,
                    target_control_id=cur_ctrl,
                    confidence=path_confidence,
                    notes=f"Transitive via {' → '.join(path)}",
                    via=path[1:-1],  # intermediate frameworks only
                ))
                continue

            # Limit search depth
            if len(path) >= 4:
                continue

            for t_fw, t_ctrl, confidence, _notes in self._graph.get((cur_fw, cur_ctrl), []):
                if (t_fw, t_ctrl) not in visited:
                    visited.add((t_fw, t_ctrl))
                    # Transitive confidence = minimum in chain
                    min_conf = self._min_confidence(path_confidence, confidence)
                    queue.append((t_fw, t_ctrl, path + [t_fw], min_conf))

        return results

    @staticmethod
    def _min_confidence(a: str, b: str) -> str:
        """Return the lower of two confidence levels."""
        rank_a = CONFIDENCE_RANK.get(a, 1)
        rank_b = CONFIDENCE_RANK.get(b, 1)
        return a if rank_a <= rank_b else b

    def map_results(
        self,
        results: list[dict],
        source_framework: str,
        target_framework: str,
    ) -> list[dict]:
        """
        Map assessment results to a target framework.

        Each result's control_id is translated. If a control maps to
        multiple target controls, the result is duplicated. Unmapped
        controls are included with mapping_confidence='unmapped'.
        """
        if source_framework == target_framework:
            for r in results:
                r["mapping_confidence"] = "high"
                r["mapping_path"] = []
                r["original_control_id"] = r.get("control_id", "")
            return results

        mapped = []
        for result in results:
            control_id = result.get("control_id", "")
            mappings = self.map_control(source_framework, control_id, target_framework)

            if not mappings:
                entry = dict(result)
                entry["original_control_id"] = control_id
                entry["mapping_confidence"] = "unmapped"
                entry["mapping_path"] = []
                mapped.append(entry)
            else:
                for m in mappings:
                    entry = dict(result)
                    entry["original_control_id"] = control_id
                    entry["control_id"] = m.target_control_id
                    entry["mapping_confidence"] = m.confidence
                    entry["mapping_path"] = m.via
                    entry["mapping_notes"] = m.notes
                    mapped.append(entry)

        return mapped

    def map_evidence(
        self,
        evidence: list[dict],
        source_framework: str,
        target_framework: str,
    ) -> list[dict]:
        """Map evidence records to a target framework's control IDs."""
        return self.map_results(evidence, source_framework, target_framework)
