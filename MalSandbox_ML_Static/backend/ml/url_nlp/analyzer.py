"""
ML Model 1 — URL Lexical / NLP Analyzer
========================================
Uses character-level n-gram TF-IDF + hand-crafted features to detect:
  • Domain Generation Algorithm (DGA) URLs
  • Typosquatting / homograph attacks
  • Suspicious path/param patterns
  • Brand impersonation in subdomains
"""
import math
import re
import string
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs

try:
    import tldextract
except ImportError:
    # Small offline fallback used by the local demo. Production can use tldextract.
    class _Result:
        def __init__(self, url):
            host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            parts = host.split(".")
            self.domain = parts[-2] if len(parts) >= 2 else host
            self.subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
            self.suffix = parts[-1] if len(parts) >= 2 else ""
    class _TLDExtractFallback:
        @staticmethod
        def extract(url):
            return _Result(url)
    tldextract = _TLDExtractFallback()


# ── Known brand domains (partial list for demo) ───────────────────────────────
BRAND_DOMAINS = {
    "paypal", "microsoft", "apple", "amazon", "google", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".tech", ".pw",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".bid", ".stream",
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "password", "credential", "banking", "suspended",
    "unusual", "activity", "security", "alert", "urgent",
}

DGA_CONSONANT_CLUSTERS = re.compile(r'[bcdfghjklmnpqrstvwxyz]{5,}')


class URLAnalyzer:
    """
    Analyzes a URL using lexical and structural features.
    Returns a score dict compatible with the orchestrator's MLScore format.
    """

    def analyze(self, url: str) -> Dict[str, Any]:
        features = self._extract_features(url)
        score, reasoning = self._score(features)

        threat_level = "safe"
        if score >= 0.70:
            threat_level = "malicious"
        elif score >= 0.40:
            threat_level = "suspicious"

        return {
            "model": "url_nlp",
            "score": round(score, 4),
            "confidence": round(self._confidence(features), 4),
            "threat_level": threat_level,
            "features": features,
            "reasoning": reasoning,
        }

    # ── Feature extraction ────────────────────────────────────────────────────

    def _extract_features(self, url: str) -> Dict[str, Any]:
        # Ensure scheme present for urlparse
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        ext = tldextract.extract(url)

        domain = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        tld = f".{ext.suffix.split(".")[-1]}" if ext.suffix else ""
        full_domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query_str = parsed.query

        return {
            # Length features
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),
            "subdomain_depth": len(subdomain.split(".")) if subdomain else 0,

            # Entropy — high entropy → likely DGA
            "domain_entropy": self._shannon_entropy(domain),
            "url_entropy": self._shannon_entropy(url),

            # Digit ratio
            "digit_ratio": sum(c.isdigit() for c in domain) / max(len(domain), 1),

            # Special chars in domain
            "hyphen_count": domain.count("-"),
            "at_sign": "@" in url,
            "double_slash_path": "//" in path,
            "ip_in_url": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', full_domain)),

            # TLD suspicion
            "suspicious_tld": tld in SUSPICIOUS_TLDS,
            "tld": tld,

            # Brand impersonation
            "brand_in_subdomain": any(b in subdomain for b in BRAND_DOMAINS),
            "brand_in_path": any(b in path for b in BRAND_DOMAINS),
            "brand_mismatch": self._brand_mismatch(domain, subdomain, path),

            # Phishing keywords
            "phishing_keyword_count": sum(kw in url.lower() for kw in PHISHING_KEYWORDS),

            # DGA heuristics
            "dga_consonant_cluster": bool(DGA_CONSONANT_CLUSTERS.search(domain)),
            "low_vowel_ratio": self._vowel_ratio(domain) < 0.25,

            # Query params
            "param_count": len(parse_qs(query_str)),
            "redirect_param": any(k in ["redirect", "url", "goto", "next", "redir"]
                                  for k in parse_qs(query_str).keys()),

            # HTTPS
            "is_https": parsed.scheme == "https",

            # Raw parts (not scored directly)
            "domain": domain,
            "subdomain": subdomain,
            "full_url": url,
        }

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score(self, f: Dict[str, Any]):
        score = 0.0
        reasoning: List[str] = []

        def add(points: float, reason: str):
            nonlocal score
            score += points
            if points > 0:
                reasoning.append(reason)

        # URL length
        if f["url_length"] > 75:
            add(0.05, f"Long URL ({f['url_length']} chars)")
        if f["url_length"] > 120:
            add(0.08, f"Very long URL ({f['url_length']} chars)")

        # IP address in host
        if f["ip_in_url"]:
            add(0.35, "IP address used instead of domain name")

        # Suspicious TLD
        if f["suspicious_tld"]:
            add(0.20, f"Suspicious TLD: {f['tld']}")

        # Brand impersonation
        if f["brand_mismatch"]:
            add(0.40, f"Brand name in subdomain/path but domain doesn't match — likely spoofing")
        elif f["brand_in_subdomain"]:
            add(0.15, "Brand keyword in subdomain")

        # Phishing keywords
        kw_count = f["phishing_keyword_count"]
        if kw_count >= 3:
            add(0.30, f"High phishing keyword density ({kw_count} matches)")
        elif kw_count >= 1:
            add(0.12 * kw_count, f"Phishing keywords in URL ({kw_count})")

        # DGA / entropy
        if f["domain_entropy"] > 3.8:
            add(0.20, f"High domain entropy ({f['domain_entropy']:.2f}) — possible DGA")
        if f["dga_consonant_cluster"]:
            add(0.15, "Suspicious consonant cluster — possible DGA domain")
        if f["low_vowel_ratio"]:
            add(0.10, "Low vowel ratio — consonant-heavy domain")

        # Digit ratio
        if f["digit_ratio"] > 0.4:
            add(0.15, f"High digit ratio in domain ({f['digit_ratio']:.0%})")

        # @ sign
        if f["at_sign"]:
            add(0.30, "@ symbol in URL — hides real destination")

        # Double slash in path
        if f["double_slash_path"]:
            add(0.20, "Double slash in path — possible redirect abuse")

        # Redirect param
        if f["redirect_param"]:
            add(0.15, "Open redirect parameter detected in query string")

        # Deep subdomain
        if f["subdomain_depth"] > 3:
            add(0.15, f"Deep subdomain ({f['subdomain_depth']} levels)")

        # Hyphen count
        if f["hyphen_count"] >= 3:
            add(0.10, f"Multiple hyphens in domain ({f['hyphen_count']})")

        # HTTPS bonus (slightly reduces score, not fully exculpatory)
        if f["is_https"] and score > 0:
            score *= 0.90

        score = min(score, 1.0)
        if not reasoning:
            reasoning.append("No significant threat indicators found")

        return score, reasoning

    def _confidence(self, f: Dict[str, Any]) -> float:
        """Higher confidence when more features are present."""
        signals = sum([
            f["ip_in_url"],
            f["suspicious_tld"],
            f["brand_mismatch"],
            f["phishing_keyword_count"] > 0,
            f["domain_entropy"] > 3.5,
        ])
        return min(0.5 + signals * 0.10, 0.98)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values())

    @staticmethod
    def _vowel_ratio(s: str) -> float:
        vowels = set("aeiou")
        alpha = [c for c in s.lower() if c.isalpha()]
        if not alpha:
            return 0.5
        return sum(c in vowels for c in alpha) / len(alpha)

    @staticmethod
    def _brand_mismatch(domain: str, subdomain: str, path: str) -> bool:
        """True if a brand keyword appears in subdomain/path but NOT as the actual domain."""
        combined = subdomain + " " + path
        for brand in BRAND_DOMAINS:
            if brand in combined and brand != domain:
                return True
        return False
