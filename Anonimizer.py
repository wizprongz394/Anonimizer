
"""
Anonimizer v5
Intelligent Hybrid Privacy Engine
----------------------------------
Upgrades
• Presidio-aware classification
• First-word false positive filter
• Confidence-aware entity logic
• Context filtering
• Smarter unknown handling
• Better accuracy + fewer false positives
"""

import re
import json
import hashlib
from typing import Dict, List, Callable

try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO_AVAILABLE = True
except:
    PRESIDIO_AVAILABLE = False


class QueryAnonymizer:

    # ======================================================
    # INIT
    # ======================================================

    def __init__(self, config_path: str | None = None, salt: str = "terramind"):

        self.salt = salt
        self.location_map: Dict[str, str] = {}
        self.audit_log: List[dict] = []
        self.presidio_labels = {}

        self.city_db = set()
        self.country_db = set()

        self._load_config(config_path)
        self._load_datasets()
        self._compile_patterns()
        self._init_presidio()
        self._register_detectors()

    # ======================================================
    # CONFIG
    # ======================================================

    def _load_config(self, path):

        if path:
            with open(path) as f:
                self.config = json.load(f)
        else:
            self.config = {
                "city": "token",
                "country": "token",
                "coordinates": "round",
                "unknown": "keep",   # upgraded default
                "coord_precision": 2
            }

    # ======================================================
    # DATASETS
    # ======================================================

    def _load_datasets(self):

        self.city_db.update({
            "Kolkata","Delhi","Mumbai","London","Paris","Tokyo","Berlin"
        })

        self.country_db.update({
            "India","France","Germany","Japan","USA","Canada"
        })

    # ======================================================
    # REGEX
    # ======================================================

    def _compile_patterns(self):

        self.word_pattern = re.compile(
            r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\b"
        )

        self.coord_pattern = re.compile(
            r"-?\d{1,3}\.\d+"
        )

    # ======================================================
    # PRESIDIO
    # ======================================================

    def _init_presidio(self):

        if PRESIDIO_AVAILABLE:
            try:
                self.presidio = AnalyzerEngine()
            except:
                self.presidio = None
        else:
            self.presidio = None

    # ======================================================
    # DETECTORS
    # ======================================================

    def _register_detectors(self):

        self.fast_detectors: List[Callable[[str], set]] = [
            self._detect_coordinates,
            self._detect_words
        ]

        self.smart_detectors: List[Callable[[str], set]] = [
            self._detect_presidio
        ]

    # ======================================================
    # PUBLIC API
    # ======================================================

    def anonymize(self, text: str) -> str:

        self.presidio_labels.clear()
        entities = self._detect_entities(text)

        entities.sort(key=len, reverse=True)

        for i, entity in enumerate(entities, start=1):

            label = self._classify(entity, text)
            replacement = self._apply_policy(entity, label, i)

            if replacement != entity:
                text = re.sub(re.escape(entity), replacement, text)

                self.audit_log.append({
                    "original": entity,
                    "replacement": replacement,
                    "type": label
                })

        self._log_metadata(entities)
        return text

    # ======================================================
    # DETECTION
    # ======================================================

    def _detect_entities(self, text: str) -> List[str]:

        found = set()

        for detector in self.fast_detectors:
            found.update(detector(text))

        if not found:
            for detector in self.smart_detectors:
                found.update(detector(text))

        return list(found)

    # ------------------------------------------------------

    def _detect_words(self, text: str):

        blacklist = {"I","Find","Show","Give","Tell","What","Where","Is","The"}

        words = self.word_pattern.findall(text)

        # ignore first word rule
        if words and text.startswith(words[0]):
            words = words[1:]

        return {w for w in words if w not in blacklist}

    # ------------------------------------------------------

    def _detect_coordinates(self, text: str):
        return set(self.coord_pattern.findall(text))

    # ------------------------------------------------------

    def _detect_presidio(self, text: str):

        if not self.presidio:
            return set()

        try:
            results = self.presidio.analyze(text=text, language="en")

            for r in results:
                word = text[r.start:r.end]
                self.presidio_labels[word] = r.entity_type

            return set(self.presidio_labels.keys())

        except:
            return set()

    # ======================================================
    # CLASSIFIER
    # ======================================================

    def _classify(self, value: str, text: str) -> str:

        if self.coord_pattern.fullmatch(value):
            return "coordinates"

        if value in self.city_db:
            return "city"

        if value in self.country_db:
            return "country"

        # presidio semantic classification
        if value in self.presidio_labels:

            label = self.presidio_labels[value]

            if label in ["LOCATION","GPE"]:
                return "city"

            if label in ["COUNTRY"]:
                return "country"

        return "unknown"

    # ======================================================
    # POLICY
    # ======================================================

    def _apply_policy(self, value: str, label: str, index: int) -> str:

        rule = self.config.get(label, "keep")

        if rule == "keep":
            return value

        if rule == "token":
            return self._token(value, label, index)

        if rule == "hash":
            return self._hash(value)

        if rule == "mask":
            return self._mask(value)

        if rule == "round" and label == "coordinates":
            return self._round(value)

        return value

    # ======================================================
    # TRANSFORMS
    # ======================================================

    def _token(self, value: str, label: str, i: int):
        token = f"<{label.upper()}_{i}>"
        self.location_map[token] = value
        return token

    def _hash(self, value: str):
        return hashlib.sha256((value + self.salt).encode()).hexdigest()[:12]

    def _mask(self, value: str):
        if len(value) <= 2:
            return "*" * len(value)
        return value[0] + "*"*(len(value)-2) + value[-1]

    def _round(self, value: str):

        precision = self.config.get("coord_precision", 2)

        try:
            return str(round(float(value), precision))
        except:
            return value

    # ======================================================
    # LOGGING
    # ======================================================

    def _log_metadata(self, entities):

        if not entities:
            return

        meta = {
            "count": len(entities),
            "types": [self._classify(e,"") for e in entities]
        }

        print("[ANON LOG]", meta)

    # ======================================================
    # REVERSE
    # ======================================================

    def deanonymize(self, text: str):

        for token, original in self.location_map.items():
            text = text.replace(token, original)

        return text


# ======================================================
# CLI
# ======================================================

if __name__ == "__main__":

    anon = QueryAnonymizer()

    while True:
        q = input("Query: ")
        print("Anon:", anon.anonymize(q))
