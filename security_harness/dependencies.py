"""Bounded lockfile SBOM and exact-version OSV queries; no package execution.

The inventory describes the declared Python lock, not installed wheels or images.
Every published advisory blocks; unknown severity is never treated as low risk.
"""
import concurrent.futures
import hashlib
import json
import re
import urllib.request
from datetime import datetime, timezone

from .preflight import NoRedirect, parse_lock
from .results import digest_file

ENDPOINT = 'https://api.osv.dev/v1/query'
MAX_PACKAGES = 128
MAX_RESPONSE = 1024**2


class DependencyError(ValueError):
    def __init__(self, message, evidence=None):
        super().__init__(message)
        self.evidence = evidence


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise DependencyError('duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise DependencyError('nonfinite JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def sbom(records):
    if not 1 <= len(records) <= MAX_PACKAGES:
        raise DependencyError('package limit')
    components = []
    for r in sorted(records, key=lambda r: r['name']):
        ref = f"pkg:pypi/{r['name']}@{r['version']}"
        components.append({'type': 'library', 'bom-ref': ref, 'name': r['name'],
                           'version': r['version'], 'purl': ref,
                           'properties': [{'name': 'epsilon:approved-artifact-sha256',
                                           'value': json.dumps(sorted(r['hashes']))}]})
    if len({c['bom-ref'] for c in components}) != len(components):
        raise DependencyError('duplicate component')
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'properties': [{'name': 'epsilon:inventory-scope',
                                        'value': 'declared requirements.lock; not installed artifacts'}]},
            'components': components}


def query(name, version):
    request = urllib.request.Request(ENDPOINT, data=encoded({
        'package': {'name': name, 'ecosystem': 'PyPI'}, 'version': version}),
        headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise DependencyError('response limit')
    return strict_json(raw)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}', value):
        raise DependencyError('invalid advisory identifier')
    return value


def findings_for(record, response):
    if not isinstance(response, dict) or set(response) - {'vulns'}:
        # next_page_token also refuses partial database coverage.
        raise DependencyError('incomplete query response')
    vulnerabilities = response.get('vulns', [])
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 256:
        raise DependencyError('invalid advisory list')
    findings, seen = [], set()
    for item in vulnerabilities:
        if not isinstance(item, dict) or item.get('withdrawn'):
            raise DependencyError('invalid advisory')
        advisory = identifier(item.get('id'))
        if advisory in seen:
            raise DependencyError('duplicate advisory')
        seen.add(advisory)
        affected = item.get('affected')
        if (not isinstance(affected, list) or not affected or
                not any(isinstance(a, dict) and isinstance(a.get('package'), dict)
                        and a['package'].get('ecosystem') == 'PyPI'
                        and a['package'].get('name') == record['name'] for a in affected)):
            raise DependencyError('advisory package mismatch')
        aliases = item.get('aliases', [])
        if not isinstance(aliases, list) or len(aliases) > 100:
            raise DependencyError('invalid aliases')
        aliases = sorted({identifier(a) for a in aliases})
        findings.append({'package': record['name'], 'version': record['version'],
                         'advisory_id': advisory, 'aliases': aliases})
    return sorted(findings, key=lambda f: f['advisory_id'])


def scan(lock, fetch=query, now=None):
    lock_hash = digest_file(lock)
    records = parse_lock(lock)
    inventory = sbom(records)
    findings, queries, incomplete = [], [], False
    # Each failed query stays in the inventory. No retries/caches.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(fetch, r['name'], r['version']) for r in records]
        for record, future in zip(records, futures, strict=True):
            item = {'name': record['name'], 'version': record['version']}
            try:
                response = future.result()
                observed = findings_for(record, response)
                findings.extend(observed)
                item.update(status='SUCCESS', response_sha256=hashlib.sha256(encoded(response)).hexdigest(),
                            advisory_ids=[f['advisory_id'] for f in observed])
            except Exception as exc:
                incomplete = True
                item.update(status='ERROR', error_type=type(exc).__name__)
            queries.append(item)
    if digest_file(lock) != lock_hash:
        raise DependencyError('lock changed during scan')
    evidence = {'schema_version': 1, 'status': 'INCOMPLETE' if incomplete else 'COMPLETE', 'source': ENDPOINT,
            'queried_at': (now or datetime.now(timezone.utc)).isoformat(),
            'lock_sha256': lock_hash, 'sbom': inventory,
            'sbom_sha256': hashlib.sha256(encoded(inventory)).hexdigest(),
            'queries': queries, 'findings': findings, 'package_count': len(records),
            'policy': 'block every reported advisory, including unknown severity',
            'limitations': ['OSV database coverage only; absence is not proof of safety',
                            'no KEV/EPSS or malicious-package behavior analysis']}
    if incomplete:
        raise DependencyError('incomplete query coverage', evidence)
    return evidence


def validate_evidence(evidence, packages, count, findings, now, max_age):
    if (not isinstance(evidence, dict) or type(evidence.get('schema_version')) is not int or evidence.get('schema_version') != 1 or
            evidence.get('status') != 'COMPLETE' or evidence.get('source') != ENDPOINT or
            type(evidence.get('package_count')) is not int or evidence['package_count'] != count or
            not re.fullmatch('[a-f0-9]{64}', evidence.get('lock_sha256', ''))):
        raise DependencyError('invalid scan identity')
    if not isinstance(packages, list) or len(packages) != count:
        raise DependencyError('missing provenance packages')
    declared = [{'name': p['name'], 'version': p['version'], 'hashes': set(p['approved_hashes'])}
                for p in packages]
    if (any(not r['hashes'] or any(not re.fullmatch('[a-f0-9]{64}', h) for h in r['hashes']) for r in declared) or
            evidence['sbom'] != sbom(declared) or
            evidence['sbom_sha256'] != hashlib.sha256(encoded(evidence['sbom'])).hexdigest()):
        raise DependencyError('SBOM mismatch')
    age = (now - datetime.fromisoformat(evidence['queried_at'])).total_seconds()
    if not 0 <= age <= max_age:
        raise DependencyError('stale scan')
    expected = {(r['name'], r['version']) for r in declared}
    queries = evidence['queries']
    if (not isinstance(queries, list) or len(queries) != count or len(expected) != count or
            {(q['name'], q['version']) for q in queries} != expected or
            any(q.get('status') != 'SUCCESS' or not re.fullmatch('[a-f0-9]{64}', q['response_sha256']) or
                not isinstance(q['advisory_ids'], list) or
                len(set(q['advisory_ids'])) != len(q['advisory_ids']) for q in queries)):
        raise DependencyError('incomplete query coverage')
    expected_findings = {(q['name'], q['version'], identifier(a)) for q in queries for a in q['advisory_ids']}
    observed = evidence['findings']
    if (not isinstance(observed, list) or len(observed) != findings or
            {(f['package'], f['version'], identifier(f['advisory_id'])) for f in observed} != expected_findings or
            len(expected_findings) != findings):
        raise DependencyError('finding summary mismatch')
