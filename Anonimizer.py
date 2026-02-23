"""
Anonimizer v8
Production-Grade Hybrid Privacy Engine
---------------------------------------
Fixes applied:
• self.ai_labels undefined → replaced with self.ai_cache label tracking
• ai_labels block moved outside presidio_labels guard
• coordinates now stored in location_map so deanonymize works
• audit_log cleared at the start of each anonymize() call
• cleaner _classify fallback chain
• nickname/alias detection for informal place references (e.g. "city of lights")
"""

import re
import json
import hashlib
import subprocess
from typing import Dict, List, Callable

# optional NLP
try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO_AVAILABLE = True
except:
    PRESIDIO_AVAILABLE = False


class QueryAnonymizer:

    # =====================================================
    # PLACE NICKNAME TABLE
    # =====================================================

    LOCATION_NICKNAMES = {
        "the city of lights":       "Paris, France",
        "city of lights":           "Paris, France",
        "the big apple":            "New York City, USA",
        "big apple":                "New York City, USA",
        "the windy city":           "Chicago, USA",
        "windy city":               "Chicago, USA",
        "the eternal city":         "Rome, Italy",
        "eternal city":             "Rome, Italy",
        "the city by the bay":      "San Francisco, USA",
        "city by the bay":          "San Francisco, USA",
        "the emerald city":         "Seattle, USA",
        "emerald city":             "Seattle, USA",
        "the city of love":         "Paris, France",
        "city of love":             "Paris, France",
        "the venice of the north":  "Amsterdam, Netherlands",
        "venice of the north":      "Amsterdam, Netherlands",
        "the forbidden city":       "Beijing, China",
        "forbidden city":           "Beijing, China",
        "the golden gate city":     "San Francisco, USA",
        "sin city":                 "Las Vegas, USA",
        "the motor city":           "Detroit, USA",
        "motor city":               "Detroit, USA",
        "the holy city":            "Jerusalem, Israel",
        "holy city":                "Jerusalem, Israel",
    }

    # =====================================================
    # INIT
    # =====================================================

    def __init__(self, salt: str = "terramind"):

        self.salt = salt
        self.location_map: Dict[str, str] = {}
        self.audit_log: List[dict] = []
        self.presidio_labels: Dict[str, str] = {}
        self.ai_labels: Dict[str, str] = {}
        self.ai_cache = {}

        self.ai_timeout = 6

        self._compile_patterns()
        self._init_presidio()
        self._register_detectors()

    # =====================================================
    # REGEX PATTERNS
    # =====================================================

    def _compile_patterns(self):

        # multi-word capitalized phrases
        self.word_pattern = re.compile(
            r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\b"
        )

        # decimal coordinates
        self.coord_pattern = re.compile(
            r"-?\d{1,3}\.\d+"
        )

    # =====================================================
    # PRESIDIO INIT
    # =====================================================

    def _init_presidio(self):

        if PRESIDIO_AVAILABLE:
            try:
                self.presidio = AnalyzerEngine()
            except:
                self.presidio = None
        else:
            self.presidio = None

    # =====================================================
    # DETECTOR REGISTRY
    # =====================================================

    def _register_detectors(self):

        self.detectors: List[Callable[[str], set]] = [

            # fastest first
            self._detect_coordinates,
            self._detect_words,
            self._detect_nicknames,    # catches lowercase place aliases

            # semantic detectors
            self._detect_presidio,
            self._detect_ollama
        ]

    # =====================================================
    # PUBLIC API
    # =====================================================

    def anonymize(self, text: str) -> str:

        # clear state at the start of each call
        self.presidio_labels.clear()
        self.ai_labels.clear()
        self.audit_log.clear()

        entities = self._detect_entities(text)

        # longest first prevents partial replacement
        entities.sort(key=len, reverse=True)

        for i, entity in enumerate(entities, start=1):

            label = self._classify(entity)
            replacement = self._transform(entity, label, i)

            if replacement != entity:

                pattern = r"(?<!\w)" + re.escape(entity) + r"(?!\w)"
                text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

                self.audit_log.append({
                    "entity": entity,
                    "label": label,
                    "replacement": replacement
                })

        self._log_summary()
        return text

    # =====================================================
    # DETECTION PIPELINE
    # =====================================================

    def _detect_entities(self, text: str) -> List[str]:

        found = set()

        for detector in self.detectors:
            try:
                result = detector(text)
                if result:
                    found.update(result)
            except:
                continue

        return list(found)

    # -----------------------------------------------------

    def _detect_coordinates(self, text):
        return set(self.coord_pattern.findall(text))

    # -----------------------------------------------------

    def _detect_words(self, text):

        blacklist = {
            "I","The","This","That","What","Where","When",
            "Why","How","Find","Show","Give","Tell",
            "Today","Yesterday","Tomorrow","Recently",
            "During","After","Before","Near","In","On","At"
        }

        words = self.word_pattern.findall(text)

        # ignore first word if sentence start
        if words and text.startswith(words[0]):
            words = words[1:]

        return {w for w in words if w not in blacklist}

    # -----------------------------------------------------

    def _detect_nicknames(self, text):
        """Match well-known lowercase place aliases against LOCATION_NICKNAMES.

        When two aliases overlap (e.g. 'city of lights' inside
        'the city of lights'), only the longest match is kept so the
        counter in anonymize() stays gapless.
        """

        lower = text.lower()

        # collect all matches as (start, end, original_span)
        matches = []
        for alias in self.LOCATION_NICKNAMES:
            pattern = r"(?<!\w)" + re.escape(alias) + r"(?!\w)"
            for m in re.finditer(pattern, lower):
                matches.append((m.start(), m.end(), text[m.start():m.end()]))

        # sort by start position, then longest first
        matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))

        # keep only non-overlapping longest matches
        kept = []
        last_end = -1
        for start, end, span in matches:
            if start >= last_end:
                kept.append(span)
                last_end = end

        for span in kept:
            self.ai_labels[span] = "location"

        return set(kept)

    # -----------------------------------------------------

    def _detect_presidio(self, text):

        if not self.presidio:
            return set()

        try:
            results = self.presidio.analyze(text=text, language="en")

            found = set()
            for r in results:
                val = text[r.start:r.end]
                self.presidio_labels[val] = r.entity_type
                found.add(val)

            return found

        except:
            return set()

    # -----------------------------------------------------
    # AI LOCATION DETECTOR
    # -----------------------------------------------------

    def _detect_ollama(self, text):

        if text in self.ai_cache:
            cached = self.ai_cache[text]
            self.ai_labels.update({loc: "location" for loc in cached})
            return cached

        prompt = f"""
Extract ALL phrases from this text that refer to locations, including
informal nicknames and aliases like "city of lights" or "big apple".
Return a JSON list of exact text spans only, no explanation.

{text}
"""

        try:
            result = subprocess.run(
                ["ollama", "run", "llama3"],
                input=prompt,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                encoding="utf-8",
                errors="ignore",
                timeout=self.ai_timeout
            )

            raw = result.stdout.strip()

            start = raw.find("[")
            end = raw.rfind("]") + 1
            if start == -1:
                return set()

            parsed = json.loads(raw[start:end])
            detected = {x.strip() for x in parsed if isinstance(x, str)}

            self.ai_cache[text] = detected
            self.ai_labels.update({loc: "location" for loc in detected})
            return detected

        except:
            return set()

    # =====================================================
    # CLASSIFICATION
    # =====================================================

    def _classify(self, value: str) -> str:

        if self.coord_pattern.fullmatch(value):
            return "coordinates"

        if value in self.presidio_labels:
            label = self.presidio_labels[value]

            if label == "PERSON":
                return "person"
            if label == "ORG":
                return "organization"
            if label in ("GPE", "LOCATION"):
                return "location"

        # ai_labels is an independent fallback (not nested in presidio block)
        if value in self.ai_labels:
            return self.ai_labels[value]

        return "entity"

    # =====================================================
    # TRANSFORMATION
    # =====================================================

    def _transform(self, value: str, label: str, i: int) -> str:

        # coordinates stored in location_map so deanonymize can restore them
        token = f"<{label.upper()}_{i}>"
        self.location_map[token] = value
        return token

    # =====================================================
    # LOGGING
    # =====================================================

    def _log_summary(self):

        if not self.audit_log:
            return

        print(f"[ANON] {len(self.audit_log)} entities anonymized")

    # =====================================================
    # REVERSE
    # =====================================================

    def deanonymize(self, text: str) -> str:

        for token, original in self.location_map.items():
            text = text.replace(token, original)

        return text


# =====================================================
# CLI
# =====================================================

if __name__ == "__main__":

    anon = QueryAnonymizer()

    while True:
        q = input("Query: ")
        anon_q = anon.anonymize(q)
        print("Anon:  ", anon_q)
        print("Deanon:", anon.deanonymize(anon_q))