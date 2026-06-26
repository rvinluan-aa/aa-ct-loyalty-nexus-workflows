#!/usr/bin/env python3
"""
nexus-fix.py — AI-powered Gradle vulnerability batch fixer for Nexus

Reads open Dependabot alerts and the project build file, asks an AI model
to triage and apply all fixes in one pass, then writes the result in place.

Usage:
  python3 nexus-fix.py --alerts /tmp/alerts.json --repo-path /tmp/repo [--provider github-models|security-pat]
"""
import argparse, json, os, re, sys, urllib.error, urllib.request

# ── AI Providers ───────────────────────────────────────────────────────────────

PROVIDERS = {
    'github-models': {
        'name': 'GitHub Models (gpt-4.1)',
        'url': 'https://models.inference.ai.azure.com/chat/completions',
        'model': 'gpt-4.1',
        'token_env': 'GITHUB_MODELS_TOKEN',  # GITHUB_TOKEN with models: read — no personal quota
    },
    'security-pat': {
        'name': 'GitHub Models via SECURITY_PAT',
        'url': 'https://models.inference.ai.azure.com/chat/completions',
        'model': 'gpt-4.1',
        'token_env': 'SECURITY_PAT',
    },
}

SYSTEM_PROMPT = """\
You are a Java/Spring Boot security expert specialising in Gradle dependency vulnerability remediation.

Given a list of open Dependabot alerts and a Gradle build file, you must:

STEP 1 — TRIAGE
Classify every alert into one bucket:
  A) Resolved by a Spring Boot MINOR-version patch upgrade (Spring Framework, Spring Security,
     Spring Web, Tomcat, Hibernate, Netty — anything managed by the Spring Boot BOM).
  B) Explicit Spring-adjacent dep declared directly, not covered by the current BOM version.
  C) Unrelated third-party library (Jackson, Log4j, etc.).

STEP 2 — SPRING BOOT FIRST (if applicable)
If the project uses Spring Boot and there are Bucket A alerts:
  - Find the current Spring Boot version from the build file.
  - Upgrade it to the latest PATCH release in the same MAJOR.MINOR line
    (e.g. 3.3.3 → 3.3.12, NOT 3.3 → 3.4).
  - This single change resolves all Bucket A CVEs transitively via the BOM.

STEP 3 — REMAINING FIXES
For Bucket B and C, update each affected dependency version to the patched version supplied.

RULES (never violate):
  - NEVER modify or add anything inside the repositories{} block.
  - NEVER add mavenCentral(), google(), jcenter(), or any public repository.
  - Prefer upgrading the parent/direct dep over adding constraints.
  - Keep all existing structure, formatting, and comments intact.
  - Do not add new comments explaining what you changed.

OUTPUT
Return ONLY the complete updated build.gradle (or build.gradle.kts) content.
No markdown fencing, no explanation, no preamble — just the file content.\
"""


# ── Helpers ────────────────────────────────────────────────────────────────────

def find_build_file(repo_path):
    for name in ('build.gradle.kts', 'build.gradle'):
        path = os.path.join(repo_path, name)
        if os.path.exists(path):
            return path
    raise FileNotFoundError(f'No build.gradle or build.gradle.kts found in {repo_path}')


def get_token(provider):
    env_var = PROVIDERS[provider]['token_env']
    token = os.environ.get(env_var, '').strip()
    if not token:
        raise RuntimeError(
            f'Token not set: ${env_var}\n'
            f'  For github-models: set GITHUB_MODELS_TOKEN to the workflow GITHUB_TOKEN.\n'
            f'  For security-pat:  set SECURITY_PAT to a GitHub PAT with repo scope.'
        )
    return token


def call_ai(provider, alerts, build_content):
    p = PROVIDERS[provider]
    token = get_token(provider)

    alerts_summary = json.dumps([
        {
            'package':         a.get('dependency', {}).get('package', {}).get('name', 'unknown'),
            'cve':             a.get('security_advisory', {}).get('cve_id', 'N/A'),
            'severity':        a.get('security_advisory', {}).get('severity', 'unknown'),
            'patched_version': (a.get('security_vulnerability', {})
                                 .get('first_patched_version', {})
                                 .get('identifier', 'unknown')),
            'summary':         a.get('security_advisory', {}).get('summary', ''),
        }
        for a in alerts
    ], indent=2)

    user_prompt = (
        f'Open Dependabot alerts to fix:\n{alerts_summary}\n\n'
        f'Current build file:\n{build_content}\n\n'
        'Return the complete updated build file.'
    )

    payload = {
        'model':       p['model'],
        'messages':    [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': user_prompt},
        ],
        'max_tokens':  8192,
        'temperature': 0.1,
    }

    body = json.dumps(payload).encode()
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    req = urllib.request.Request(p['url'], data=body, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{p['name']} API error {e.code}: {e.read().decode()[:500]}")

    content = data['choices'][0]['message']['content'].strip()

    # Strip markdown fencing if the model includes it despite instructions
    content = re.sub(r'^```(?:groovy|gradle|kotlin|java)?\s*\n', '', content)
    content = re.sub(r'\n```\s*$', '', content).strip()

    return content


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='AI-powered Gradle vulnerability batch fixer')
    parser.add_argument('--alerts',    required=True, help='Path to Dependabot alerts JSON')
    parser.add_argument('--repo-path', required=True, help='Path to cloned target repo')
    parser.add_argument('--provider',  choices=list(PROVIDERS.keys()), default='github-models')
    args = parser.parse_args()

    with open(args.alerts) as f:
        alerts = json.load(f)

    if not alerts:
        print('No alerts — nothing to fix.')
        sys.exit(0)

    print(f'Processing {len(alerts)} alert(s) with {PROVIDERS[args.provider]["name"]}...')
    for a in alerts:
        pkg = a.get('dependency', {}).get('package', {}).get('name', '?')
        cve = a.get('security_advisory', {}).get('cve_id', 'N/A')
        sev = a.get('security_advisory', {}).get('severity', '?').upper()
        ver = (a.get('security_vulnerability', {})
                .get('first_patched_version', {})
                .get('identifier', '?'))
        print(f'  [{sev}] {pkg} — {cve} → patch: {ver}')

    build_file = find_build_file(args.repo_path)
    print(f'\nBuild file: {build_file}')
    with open(build_file) as f:
        original = f.read()

    print('Calling AI...')
    updated = call_ai(args.provider, alerts, original)

    if len(updated) < 100:
        raise RuntimeError(f'AI returned suspiciously short output ({len(updated)} chars): {updated[:200]}')

    with open(build_file, 'w') as f:
        f.write(updated)
        if not updated.endswith('\n'):
            f.write('\n')

    print(f'✓ Written: {build_file}')


if __name__ == '__main__':
    main()
