import re
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from cadresec.core.evidence import Evidence


class TechnologyProfile(BaseModel):
    technology: str = Field(..., description="Name of the detected technology (e.g. Nginx, WordPress)")
    category: str = Field(..., description="Category of the technology (e.g. Web Server, CMS)")
    version: Optional[str] = Field(None, description="Detected version string if available")
    confidence: float = Field(..., description="Aggregated confidence score between 0.0 and 1.0")
    evidence: List[str] = Field(default_factory=list, description="Descriptions of supporting evidence")


class FingerprintEngine:
    def __init__(self):
        # Default rules dictionary mapping technology to detection pattern and category
        # Each rule is: (evidence_category, regex_pattern, category_name, confidence, version_regex)
        self.rules = [
            # Web Servers
            ("server", r"(?i)nginx(?:/([\d\.]+))?", "Web Server", "Nginx", 1.0, r"(?i)nginx/([\d\.]+)"),
            ("server", r"(?i)apache(?:/([\d\.]+))?", "Web Server", "Apache", 1.0, r"(?i)apache/([\d\.]+)"),
            ("server", r"(?i)microsoft-iis(?:/([\d\.]+))?", "Web Server", "IIS", 1.0, r"(?i)iis/([\d\.]+)"),
            ("server", r"(?i)caddy(?:/([\d\.]+))?", "Web Server", "Caddy", 1.0, r"(?i)caddy/([\d\.]+)"),
            ("server", r"(?i)litespeed", "Web Server", "LiteSpeed", 1.0, None),
            ("banner", r"(?i)ssh-([\d\.]+)-openssh_([\d\.]+)", "Service", "OpenSSH", 1.0, r"(?i)openssh_([\d\.]+)"),

            # CDNs & Cloud Providers
            ("server", r"(?i)cloudflare", "CDN / Cloud Provider", "Cloudflare", 1.0, None),
            ("header", r"(?i)cf-ray|cf-cache-status", "CDN / Cloud Provider", "Cloudflare", 0.95, None),
            ("header", r"(?i)x-amz-|x-amzn-", "Cloud Provider", "Amazon Web Services (AWS)", 0.95, None),
            ("header", r"(?i)x-vercel-", "Cloud Provider", "Vercel", 0.95, None),
            ("header", r"(?i)server:\s*netlify", "Cloud Provider", "Netlify", 0.95, None),

            # CMS
            ("html", r"(?i)/wp-content/|/wp-includes/|wp-submit", "CMS", "WordPress", 0.95, None),
            ("meta", r"(?i)wordpress\s*([\d\.]+)?", "CMS", "WordPress", 1.0, r"(?i)wordpress\s*([\d\.]+)"),
            ("cookie", r"(?i)wordpress_logged_in_|wp-settings-", "CMS", "WordPress", 1.0, None),

            # Frontend Frameworks & Libraries
            ("html", r"(?i)data-reactroot|react-root|__react", "Frontend Framework", "React", 0.9, None),
            ("html", r"(?i)/_next/static/", "Frontend Framework / CMS", "Next.js", 0.95, None),
            ("header", r"(?i)x-nextjs-cache", "Frontend Framework / CMS", "Next.js", 0.99, None),
            ("cookie", r"(?i)__next_preview_data", "Frontend Framework / CMS", "Next.js", 0.95, None),
            ("html", r"(?i)data-v-[a-f\d]+|__vue__", "Frontend Framework", "Vue.js", 0.9, None),
            ("script", r"(?i)jquery(?:-([\d\.]+))?(?:\.min)?\.js", "JavaScript Library", "jQuery", 0.9, r"(?i)jquery(?:-([\d\.]+))?"),
            ("html", r"(?i)class=.*container.*col-", "CSS Framework", "Bootstrap", 0.5, None),
            ("html", r"(?i)class=.*space-y-|bg-[\w]+-\d+", "CSS Framework", "Tailwind CSS", 0.5, None),

            # Backend Frameworks & Programming Languages
            ("header", r"(?i)x-powered-by:.*php/([\d\.]+)", "Programming Language", "PHP", 0.99, r"(?i)php/([\d\.]+)"),
            ("cookie", r"(?i)PHPSESSID", "Programming Language", "PHP", 0.95, None),
            ("header", r"(?i)server:\s*(?:gunicorn|uwsgi)", "Programming Language", "Python", 0.8, None),
            ("cookie", r"(?i)csrftoken", "Backend Framework", "Django", 0.7, None),
            ("html", r"(?i)csrfmiddlewaretoken", "Backend Framework", "Django", 0.9, None),
            ("header", r"(?i)x-powered-by:.*express", "Backend Framework", "Express", 0.9, None),

            # Authentication Providers
            ("cookie", r"(?i)next-auth\.session-token|__Secure-next-auth\.session-token", "Authentication Provider", "NextAuth.js", 1.0, None),
            ("cookie", r"(?i)auth0", "Authentication Provider", "Auth0", 1.0, None),
            ("cookie", r"(?i)firebaseauth", "Authentication Provider", "Firebase Auth", 1.0, None),
        ]

    def analyze(self, evidence_list: List[Evidence]) -> List[TechnologyProfile]:
        """Consumes a list of Evidence objects, evaluates rules, aggregates results,

        and returns a sorted list of matched TechnologyProfiles.
        """
        matches: Dict[str, Dict[str, Any]] = {}

        for evidence in evidence_list:
            for rule in self.rules:
                ev_cat, pattern, tech_cat, tech_name, weight, ver_pattern = rule
                # Match evidence category
                if evidence.category.lower() == ev_cat.lower():
                    # Match pattern
                    match = re.search(pattern, evidence.value)
                    if match:
                        # Extract version if applicable
                        version = None
                        if ver_pattern:
                            ver_match = re.search(ver_pattern, evidence.value)
                            if ver_match and ver_match.groups():
                                version = ver_match.group(1)
                        elif len(match.groups()) > 0 and match.group(1):
                            version = match.group(1)

                        desc = f"Matched {evidence.source} evidence '{evidence.value}' (confidence: {weight:.2f}) from {evidence.originating_tool}"

                        if tech_name not in matches:
                            matches[tech_name] = {
                                "technology": tech_name,
                                "category": tech_cat,
                                "version": version,
                                "confidence": weight,
                                "evidence": [desc]
                            }
                        else:
                            # Update confidence using probabilistic OR to combine evidence
                            existing = matches[tech_name]
                            existing["confidence"] = max(existing["confidence"], weight)
                            if version and not existing["version"]:
                                existing["version"] = version
                            if desc not in existing["evidence"]:
                                existing["evidence"].append(desc)

        # Convert matches to TechnologyProfile models and sort by confidence descending
        profiles = []
        for name, data in matches.items():
            profiles.append(TechnologyProfile(
                technology=data["technology"],
                category=data["category"],
                version=data["version"],
                confidence=data["confidence"],
                evidence=data["evidence"]
            ))

        return sorted(profiles, key=lambda p: p.confidence, reverse=True)
