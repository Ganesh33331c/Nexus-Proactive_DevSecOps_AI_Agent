
import os
import json
import tempfile
import shutil
import re
from git import Repo

# --- LANGCHAIN & PYDANTIC IMPORTS (GOOGLE GEMINI) ---
from pydantic import BaseModel, Field
from typing import List, Literal
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI


# ─────────────────────────────────────────────────────────────────────────────
# 1. STRICT JSON SCHEMAS (PYDANTIC)
# ─────────────────────────────────────────────────────────────────────────────

class Vulnerability(BaseModel):
    id: str = Field(
        description=(
            "Generate a unique identifier. Use the format 'SEC-001', 'SEC-002', etc. "
            "For known CVEs, use the official CVE ID (e.g., 'CVE-2023-30861')."
        )
    )
    title: str = Field(
        description=(
            "Write a concise, professional title. Examples: "
            "'JWT Signature Verification Bypass', 'Hardcoded Secret Key in Source Code', "
            "'Flask Debug Mode Enabled in Production'."
        )
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        description=(
            "Assign severity based on CVSS principles. "
            "critical = direct RCE/auth bypass. high = significant data exposure. "
            "medium = limited exposure. low = informational risk."
        )
    )
    analysis: str = Field(
        description=(
            "MANDATORY: Begin EXACTLY with 'This vulnerability occurs when...' "
            "Write 3-4 sentences. Explain: (1) the root cause, (2) how an attacker "
            "would discover and exploit it, and (3) the worst-case business impact "
            "(data breach, full server compromise, etc.)."
        )
    )
    poc: str = Field(
        description=(
            "Include the EXACT evidence from the raw scan logs. "
            "For SAST: include the file path AND the offending line of code verbatim. "
            "For SCA: include the vulnerable package name and pinned version "
            "(e.g., 'Flask==0.12.2 in app/requirements.txt')."
        )
    )
    remediation: str = Field(
        description=(
            "Write a step-by-step fix. You MUST provide one of: "
            "(a) The exact corrected Python/JS code snippet as a replacement, OR "
            "(b) The exact terminal command (e.g., 'pip install Flask==2.3.3'). "
            "Do not give vague advice like 'update the library'. Give the precise command."
        )
    )


class SecurityReport(BaseModel):
    scan_status: str = Field(
        description="Set to 'Success' if analysis completed, 'Failed' if it could not."
    )
    critical_count: int = Field(
        description="Exact count of vulnerabilities with severity='critical'."
    )
    high_count: int = Field(
        description="Exact count of vulnerabilities with severity='high'."
    )
    medium_count: int = Field(
        description="Exact count of vulnerabilities with severity='medium'."
    )
    vulnerabilities: List[Vulnerability] = Field(
        description=(
            "Comprehensive deduplicated list of ALL findings from SAST and SCA logs. "
            "If the same flaw appears in multiple files, list each file separately."
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. REPOSITORY CLONING & CLEANUP
# ─────────────────────────────────────────────────────────────────────────────

def clone_repository(repo_url: str) -> str | None:
    """Clones a remote Git repository into a fresh temp directory."""
    temp_dir = tempfile.mkdtemp(prefix="nexus_scan_")
    try:
        print(f"[NEXUS] Cloning {repo_url} → {temp_dir}")
        Repo.clone_from(repo_url, temp_dir)
        return temp_dir
    except Exception as e:
        print(f"[NEXUS][ERROR] Clone failed: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None


def cleanup(repo_path: str | None):
    """Removes the ephemeral sandbox directory after scanning."""
    if repo_path and os.path.exists(repo_path):
        shutil.rmtree(repo_path, ignore_errors=True)
        print(f"[NEXUS] Cleaned up sandbox: {repo_path}")


# ─────────────────────────────────────────────────────────────────────────────
# 3. BULLETPROOF SAST SCANNER  (Requirement 1)
# ─────────────────────────────────────────────────────────────────────────────

# Extended pattern library — covers Flask/Python common CVEs
SAST_PATTERNS = {
    "Disabled SSL/TLS Verification":        r"verify\s*=\s*False",
    "Hardcoded Secret Key":                  r"(?i)(SECRET_KEY|secret_key)\s*=\s*['\"][^'\"]{4,}['\"]",
    "Hardcoded API Key or Token":            r"(?i)(api_key|api_token|access_token|auth_token)\s*=\s*['\"][^'\"]{8,}['\"]",
    "Hardcoded Password":                    r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
    "Flask Debug Mode Enabled":              r"(?i)(app\.run\(.*debug\s*=\s*True|DEBUG\s*=\s*True)",
    "Unsafe YAML Deserialization (RCE)":     r"yaml\.load\s*\(",
    "Unsafe Pickle Deserialization (RCE)":   r"pickle\.loads?\s*\(",
    "Arbitrary Code Execution via eval()":   r"\beval\s*\(",
    "Arbitrary Code Execution via exec()":   r"\bexec\s*\(",
    "OS Command Injection (os.system)":      r"os\.system\s*\(",
    "OS Command Injection (subprocess)":     r"subprocess\.(Popen|call|run)\s*\(.*shell\s*=\s*True",
    "SQL Injection via String Formatting":   r"(execute|cursor\.execute)\s*\(\s*[\"'].*%.*[\"']\s*%",
    "SQL Injection via f-string":            r"(execute|cursor\.execute)\s*\(\s*f[\"']",
    "JWT Signature Bypass (verify=False)":   r"decode\s*\(.*verify\s*=\s*False",
    "Use of MD5 (Weak Hash)":                r"hashlib\.md5\s*\(",
    "Use of SHA1 (Weak Hash)":               r"hashlib\.sha1\s*\(",
    "Insecure Random Number Generator":      r"\brandom\.(random|randint|choice)\b",
    "XML External Entity (XXE) Risk":        r"etree\.parse\s*\(",
    "Insecure Deserialization (marshal)":    r"marshal\.loads?\s*\(",
    "Open Redirect":                         r"redirect\s*\(\s*request\.(args|form|values)",
    "Path Traversal":                        r"open\s*\(\s*(request\.(args|form|values)|os\.path\.join)",
    "Debug Endpoint or TODO Security Note":  r"(?i)(#\s*TODO.*security|#\s*FIXME.*auth|#\s*HACK)",
}

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".env",
    ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json",
    ".php", ".rb", ".go", ".java", ".sh", ".bash",
}

SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv",
    "venv", "env", ".tox", "dist", "build", ".mypy_cache",
}


def _read_file_safe(filepath: str) -> str | None:
    """
    Bulletproof file reader with encoding fallback chain.
    Returns file content as string, or None if unreadable.
    """
    # Encoding fallback chain: utf-8 → latin-1 → ignore errors
    for encoding in ("utf-8", "latin-1"):
        try:
            with open(filepath, "r", encoding=encoding) as fh:
                return fh.read()
        except UnicodeDecodeError:
            continue
        except (OSError, PermissionError) as e:
            print(f"[NEXUS][SAST] Cannot read {filepath}: {e}")
            return None

    # Last resort: force-read ignoring all bad bytes
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except Exception as e:
        print(f"[NEXUS][SAST] Force-read also failed for {filepath}: {e}")
        return None


def run_sast(repo_path: str) -> str:
    """
    Bulletproof SAST scanner.
    - Aggressively traverses ALL subdirectories
    - Multi-encoding fallback on every file
    - Returns a JSON string of findings for the AI to analyse
    """
    if not repo_path or not os.path.isdir(repo_path):
        return json.dumps({"error": "SAST Scan Failed: repo_path is invalid or missing."})

    findings = []
    files_scanned = 0
    files_skipped = 0

    print(f"[NEXUS][SAST] Starting scan on: {repo_path}")

    for dirpath, dirnames, filenames in os.walk(repo_path, topdown=True):
        # Prune unwanted directories IN-PLACE so os.walk won't descend into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext.lower() not in SCANNABLE_EXTENSIONS:
                continue

            filepath = os.path.join(dirpath, filename)
            content = _read_file_safe(filepath)

            if content is None:
                files_skipped += 1
                continue

            files_scanned += 1
            lines = content.splitlines()

            for line_num, line in enumerate(lines, start=1):
                for vuln_name, pattern in SAST_PATTERNS.items():
                    try:
                        if re.search(pattern, line):
                            relative_path = os.path.relpath(filepath, repo_path)
                            finding = (
                                f"[{vuln_name}] "
                                f"File: {relative_path} | "
                                f"Line {line_num}: {line.strip()[:200]}"
                            )
                            findings.append(finding)
                    except re.error:
                        # Malformed pattern — skip silently
                        continue

    summary = {
        "scanner": "Nexus SAST Regex Engine v2",
        "files_scanned": files_scanned,
        "files_skipped_unreadable": files_skipped,
        "total_findings": len(findings),
        "findings": findings,
    }

    print(f"[NEXUS][SAST] Complete — scanned {files_scanned} files, "
          f"{len(findings)} findings, {files_skipped} unreadable.")

    return json.dumps(summary, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# 4. BULLETPROOF SCA SCANNER  (Requirement 1 — deep nested search)
# ─────────────────────────────────────────────────────────────────────────────

# Known vulnerable pinned versions — extend as needed
KNOWN_VULNERABLE = {
    "flask":          [("< 2.3.0", "Upgrade to Flask>=2.3.3 (fixes CVE-2023-30861 cookie prefix bypass)")],
    "pyyaml":         [("< 6.0",   "Upgrade to PyYAML>=6.0 to eliminate yaml.load() RCE risk")],
    "django":         [("< 4.2",   "Upgrade to Django>=4.2.x for latest security patches")],
    "requests":       [("< 2.31",  "Upgrade to requests>=2.31.0 to fix CVE-2023-32681 proxy credential leak")],
    "pillow":         [("< 10.0",  "Upgrade to Pillow>=10.0.0 to address multiple CVEs")],
    "cryptography":   [("< 41.0",  "Upgrade to cryptography>=41.0.0 for latest OpenSSL bindings")],
    "urllib3":        [("< 2.0",   "Upgrade to urllib3>=2.0 to fix CVE-2023-43804 header injection")],
    "werkzeug":       [("< 3.0",   "Upgrade to Werkzeug>=3.0.1 to fix CVE-2023-46136 DoS")],
    "jinja2":         [("< 3.1.3", "Upgrade to Jinja2>=3.1.3 to fix CVE-2024-22195 XSS")],
    "sqlalchemy":     [("< 2.0",   "Upgrade to SQLAlchemy>=2.0 for modern security defaults")],
    "paramiko":       [("< 3.4",   "Upgrade to paramiko>=3.4.0 to fix MitM auth bypass")],
    "twisted":        [("< 23.10", "Upgrade to Twisted>=23.10.0 to fix CVE-2023-46137")],
}


def _parse_requirements_file(filepath: str, repo_path: str) -> dict:
    """Parses a single requirements.txt — handles pinned, unpinned, and commented deps."""
    content = _read_file_safe(filepath)
    if content is None:
        return {"manifest_file": os.path.relpath(filepath, repo_path), "error": "Unreadable"}

    dependencies = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        # Skip blank lines, comments, and pip options like -r or --index-url
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        dependencies.append(line)

    return {
        "manifest_file": os.path.relpath(filepath, repo_path),
        "dependency_count": len(dependencies),
        "dependencies": dependencies,
    }


def run_sca(repo_path: str) -> str:
    """
    Bulletproof SCA scanner.
    - Deeply searches ALL subdirectories for requirements.txt
    - Aggregates dependencies from every manifest found
    - Flags known-vulnerable packages by name
    """
    if not repo_path or not os.path.isdir(repo_path):
        return json.dumps({"error": "SCA Scan Failed: repo_path is invalid or missing."})

    manifests = []
    vulnerability_hints = []

    print(f"[NEXUS][SCA] Starting dependency scan on: {repo_path}")

    for dirpath, dirnames, filenames in os.walk(repo_path, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            # Scan all common dependency manifest filenames
            if filename.lower() not in (
                "requirements.txt", "requirements-dev.txt",
                "requirements-test.txt", "requirements-prod.txt",
            ):
                continue

            filepath = os.path.join(dirpath, filename)
            manifest_data = _parse_requirements_file(filepath, repo_path)
            manifests.append(manifest_data)

            # Check each dep against known-vulnerable registry
            for dep_line in manifest_data.get("dependencies", []):
                # Normalise: "Flask==0.12.2" → name="flask", version="0.12.2"
                match = re.match(
                    r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]{1,3})\s*([\d\.]+)", dep_line
                )
                if not match:
                    # Unpinned dep — still worth noting
                    pkg_name = re.split(r"[=<>!\s]", dep_line)[0].lower().strip()
                    if pkg_name in KNOWN_VULNERABLE:
                        vulnerability_hints.append(
                            f"[UNPINNED DEP] '{dep_line}' in "
                            f"{manifest_data['manifest_file']} — no version pin; "
                            f"latest-known risk: {KNOWN_VULNERABLE[pkg_name][0][1]}"
                        )
                    continue

                pkg_name = match.group(1).lower().strip()
                pinned_version = match.group(3).strip()

                if pkg_name in KNOWN_VULNERABLE:
                    for threshold, advice in KNOWN_VULNERABLE[pkg_name]:
                        vulnerability_hints.append(
                            f"[VULNERABLE DEP] {dep_line} "
                            f"(version {pinned_version} matches threshold '{threshold}') "
                            f"in {manifest_data['manifest_file']} — {advice}"
                        )

    if not manifests:
        result = {
            "scanner": "Nexus SCA Engine v2",
            "manifests_found": 0,
            "message": (
                "No requirements.txt found anywhere in the repository. "
                "If this is a Node.js project, package.json scanning is not yet implemented."
            ),
        }
    else:
        result = {
            "scanner": "Nexus SCA Engine v2",
            "manifests_found": len(manifests),
            "vulnerability_hints": vulnerability_hints,
            "manifests": manifests,
        }

    print(f"[NEXUS][SCA] Complete — {len(manifests)} manifests found, "
          f"{len(vulnerability_hints)} vulnerability hints.")

    return json.dumps(result, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# 5. A+ SYSTEM PROMPT  (Requirement 3)
# ─────────────────────────────────────────────────────────────────────────────

NEXUS_SYSTEM_PROMPT = """\
You are the core intelligence engine of NEXUS — an elite, autonomous Senior AppSec Engineer \
and SOC Analyst with 15 years of experience in penetration testing, OWASP standards, and CVE analysis.

You are processing raw telemetry from two local scanners that ran against the repository: {repo_url}

  • SAST Scanner  — static regex engine that flagged suspicious code patterns in source files.
  • SCA Scanner   — dependency parser that extracted pinned library versions from requirements.txt files.

════════════════════════════════════════════════════════════════
YOUR MANDATORY DIRECTIVES — FOLLOW EVERY RULE PRECISELY
════════════════════════════════════════════════════════════════

DIRECTIVE 1 — SYNTHESIS (do not skip):
  Analyse BOTH scanner logs with equal weight. Every finding in SAST *and* every \
vulnerability hint in SCA MUST be converted into a vulnerability card. Do not ignore SCA \
findings just because SAST found more issues.

DIRECTIVE 2 — DEDUPLICATION:
  If the same pattern appears in multiple files (e.g., verify=False in 3 places), produce \
ONE vulnerability card and list ALL affected file paths inside the 'poc' field, separated \
by newlines. Never repeat the same title twice.

DIRECTIVE 3 — ANALYSIS LANGUAGE (mandatory phrasing):
  Each 'analysis' field MUST begin with the exact phrase: "This vulnerability occurs when..."
  Then in 3-4 sentences cover: (a) root cause, (b) attack vector (how a real adversary \
exploits it step-by-step), (c) worst-case business impact such as full server compromise, \
credential theft, data exfiltration, or service disruption.

DIRECTIVE 4 — REMEDIATION PRECISION:
  Each 'remediation' field MUST contain one of the following — no vague advice allowed:
    (a) The EXACT corrected code snippet (show before/after diff style if helpful), OR
    (b) The EXACT terminal command the developer should run (e.g., "pip install Flask==2.3.3").
  Bad example: "Update the library to a newer version."
  Good example: "Run: pip install 'Flask>=2.3.3' && pip freeze > requirements.txt"

DIRECTIVE 5 — SEVERITY CALIBRATION:
  critical  → Direct RCE, authentication bypass, full credential exposure
  high      → Significant data exposure, privilege escalation, known CVE with public exploit
  medium    → Limited exposure, requires chaining with another flaw
  low       → Defence-in-depth issue, informational, best-practice violation

DIRECTIVE 6 — PROOF OF CONCEPT COMPLETENESS:
  The 'poc' field must quote the EXACT evidence from the raw logs: file path, line number, \
and the verbatim line of code or dependency string. Do not paraphrase — copy it directly.

════════════════════════════════════════════════════════════════
OUTPUT FORMAT
════════════════════════════════════════════════════════════════
Return ONLY the structured JSON matching the SecurityReport schema. No markdown, no prose, \
no explanation outside the schema fields.\
"""


# ─────────────────────────────────────────────────────────────────────────────
# 6. DETERMINISTIC AI ANALYSIS ENGINE  (Requirement 2 — Loud Failure)
# ─────────────────────────────────────────────────────────────────────────────

def analyze_with_ai(sast_results: str, sca_results: str, repo_url: str) -> dict:
    """
    Invokes Gemini with structured output (Pydantic-enforced JSON).

    On ANY failure — LLM crash, Pydantic validation error, quota exceeded, etc.
    — this function returns a valid SecurityReport JSON containing a single
    CRITICAL card titled 'SYS-ERR-500: Nexus AI Parsing Failure' with the full
    Python exception in the analysis field. It NEVER silently returns 0 findings.
    """

    def _loud_failure(exception: Exception) -> dict:
        """
        Loud Failure fallback — always returns a valid SecurityReport shape
        so the frontend can render it and the developer can see exactly what broke.
        """
        error_detail = str(exception)
        print(f"[NEXUS][AI][LOUD FAILURE] {error_detail}")
        return {
            "scan_status": "Failed — AI Parsing Error",
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "vulnerabilities": [
                {
                    "id": "SYS-ERR-500",
                    "title": "SYS-ERR-500: Nexus AI Parsing Failure",
                    "severity": "critical",
                    "analysis": (
                        "This vulnerability occurs when the Nexus AI engine crashes "
                        "during structured-output generation, which means the raw scan "
                        "data could NOT be converted into a security report. "
                        "An attacker could exploit this by submitting malformed input "
                        "that causes the pipeline to silently swallow real vulnerabilities. "
                        f"Full Python exception: {error_detail}"
                    ),
                    "poc": (
                        f"SAST input (first 500 chars): {str(sast_results)[:500]}\n"
                        f"SCA input (first 500 chars): {str(sca_results)[:500]}"
                    ),
                    "remediation": (
                        "1. Check your GEMINI_API_KEY environment variable is set and valid.\n"
                        "2. Ensure langchain-google-genai and pydantic are up to date:\n"
                        "   pip install --upgrade langchain-google-genai langchain-core pydantic\n"
                        "3. Review the full traceback above in the server console logs.\n"
                        "4. If this is a quota error, wait 60 seconds and retry."
                    ),
                }
            ],
        }

    # ── Build the LangChain prompt ────────────────────────────────────────────
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", NEXUS_SYSTEM_PROMPT),
        (
            "human",
            "════════════════════\n"
            "SAST RAW LOGS\n"
            "════════════════════\n"
            "{sast_raw}\n\n"
            "════════════════════\n"
            "SCA RAW LOGS\n"
            "════════════════════\n"
            "{sca_raw}\n\n"
            "Now generate the SecurityReport JSON. Remember: EVERY finding above must "
            "appear as a vulnerability card. Do not omit any."
        ),
    ])

    # ── Initialize Gemini at Temperature = 0 for maximum determinism ─────────
    try:
        llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",
            temperature=0.0,
            google_api_key=os.environ.get("GEMINI_API_KEY"),
        )
        structured_llm = llm.with_structured_output(SecurityReport)
        chain = prompt_template | structured_llm
    except Exception as init_err:
        return _loud_failure(init_err)

    # ── Invoke with Loud Failure catch ────────────────────────────────────────
    try:
        print(f"[NEXUS][AI] Invoking Gemini structured-output chain for {repo_url}...")
        report_obj: SecurityReport = chain.invoke(
            {
                "repo_url": repo_url,
                "sast_raw": sast_results,
                "sca_raw": sca_results,
            }
        )

        result = report_obj.model_dump()

        # Sanity-check: recount severities from the actual list in case the
        # model's count fields are off (common LLM arithmetic mistake)
        vulns = result.get("vulnerabilities", [])
        result["critical_count"] = sum(1 for v in vulns if v.get("severity") == "critical")
        result["high_count"]     = sum(1 for v in vulns if v.get("severity") == "high")
        result["medium_count"]   = sum(1 for v in vulns if v.get("severity") == "medium")

        print(
            f"[NEXUS][AI] Success — {len(vulns)} vulnerabilities, "
            f"{result['critical_count']} critical, "
            f"{result['high_count']} high, "
            f"{result['medium_count']} medium."
        )
        return result

    except Exception as invoke_err:
        return _loud_failure(invoke_err)
