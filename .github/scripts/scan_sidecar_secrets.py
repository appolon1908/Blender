"""Complete scans with trusted controls; source comments/configuration cannot suppress findings."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import string
import subprocess
import tempfile
import tomllib


# Public C algorithm expressions, independently byte-matched to official Blender.
# Digest tables are separate from detector labels so metadata is not mistaken for credentials.
PUBLIC_REPOSITORY = 'appolon1908/Blender'
PUBLIC_PATH = 'extern/xxhash/xxhash.h'
PUBLIC_COMMIT = 'eb34d656c6a261d00a7063f72167c66cc9002c4c'
PUBLIC_BLOB = '76a5ec3cb0913778b884d83fb8e595c3235b783c'
PUBLIC_SHA256 = 'fca9abd96bc02f57ab5f617d06abed591b253dd9857f966acf8b0adae92e0dc2'
PUBLIC_LINES = {
    4593: 'db13cd6e3f52846c2848ccd0e42fc5d7efdb96436e7553872073f730dc09e5c8',
    4642: 'bf8bb5f0e8e46e370c03ccc1adcb15ac3c37db0233285aacf6e8823c9d7cc0c6',
}


def public_algorithm_bytes(data, line):
    header = ('blob ' + str(len(data)) + '\0').encode()
    lines = data.splitlines(keepends=True)
    return (hashlib.sha1(header + data).hexdigest() == PUBLIC_BLOB
            and hashlib.sha256(data).hexdigest() == PUBLIC_SHA256
            and line in PUBLIC_LINES and len(lines) >= line
            and hashlib.sha256(lines[line - 1]).hexdigest() == PUBLIC_LINES[line])


def unapproved(findings, repository, kind, root):
    """No scanner ignores: classify only four immutable, reviewed public expressions."""
    unknown, seen = [], set()
    for item in findings:
        line = item.get('StartLine')
        commit = PUBLIC_COMMIT if kind == 'git' else ''
        fingerprint = ((commit + ':') if commit else '') + PUBLIC_PATH + ':generic-api-key:' + str(line)
        exact = (repository == PUBLIC_REPOSITORY and kind in ('git', 'dir')
                 and type(line) is int and line in PUBLIC_LINES
                 and type(item.get('EndLine')) is int and item['EndLine'] == line
                 and item.get('File') == PUBLIC_PATH and item.get('RuleID') == 'generic-api-key'
                 and item.get('Commit') == commit and item.get('Fingerprint') == fingerprint
                 and fingerprint not in seen)
        if exact:
            data = (subprocess.check_output(['git', 'show', commit + ':' + PUBLIC_PATH], cwd=root)
                    if kind == 'git' else (root / PUBLIC_PATH).read_bytes())
            exact = public_algorithm_bytes(data, line)
        if exact:
            seen.add(fingerprint)
        else:
            unknown.append(item)
    return unknown


class ForbiddenSourceIgnore(ValueError):
    pass


def command(scanner, config, ignore, kind, target, report):
    if kind not in ('git', 'dir'):
        raise ValueError('Unknown scanner scope')
    return [str(scanner), kind, '--no-banner', '--redact=100', '--exit-code', '1',
            '--ignore-gitleaks-allow', '--config', str(config),
            '--gitleaks-ignore-path', str(ignore), '--report-format', 'json',
            '--report-path', str(report), str(target)]


def scan(scanner, config, ignore, kind, root, report, env=None):
    # Gitleaks loads source/.gitleaksignore additively even when -i is explicit.
    # This reviewed lane has no exemptions; do not let that implicit file exist.
    source_ignore = root / '.gitleaksignore'
    if source_ignore.exists() or source_ignore.is_symlink():
        raise ForbiddenSourceIgnore('Candidate .gitleaksignore is forbidden')
    report.unlink(missing_ok=True)
    result = subprocess.run(command(scanner, config, ignore, kind, '.', report),
                            cwd=root, env=env, capture_output=True)
    findings = json.loads(report.read_text())
    if (type(result.returncode) is not int or result.returncode not in (0, 1)
            or not isinstance(findings, list) or (result.returncode == 1) != bool(findings)
            or any(not isinstance(item, dict) for item in findings)):
        raise ValueError('Scanner error, malformed report or status/report mismatch')
    return findings


def verify_controls(scanner, config, ignore):
    parsed = tomllib.loads(config.read_text())
    if (set(parsed) != {'extend'} or set(parsed['extend']) != {'useDefault'}
            or parsed['extend']['useDefault'] is not True):
        raise ValueError('Only the trusted complete built-in rule set is allowed')
    if ignore.read_bytes() != b'':
        raise ValueError('This reviewed lane permits no fingerprint exemptions')
    with tempfile.TemporaryDirectory() as fixture, tempfile.TemporaryDirectory() as reports:
        root = Path(fixture)
        # Generated locally, never issued or sent anywhere; values are never printed.
        token = 'ghp_' + ''.join(secrets.SystemRandom().sample(string.ascii_letters + string.digits, 36))
        (root / 'credential.py').write_text('api_key = "' + token + '" # gitleaks:allow\n')
        report = Path(reports) / 'probe.json'
        control = scan(scanner, config, ignore, 'dir', root, report)
        matches = [item for item in control if item.get('RuleID') == 'github-pat'
                   and item.get('File', '').endswith('credential.py')]
        if not matches:
            raise ValueError('Inline allow comment concealed a generated credential')
        (root / '.gitleaksignore').write_text('\n'.join(item['Fingerprint'] for item in control) + '\n')
        try:
            scan(scanner, config, ignore, 'dir', root, report)
        except ForbiddenSourceIgnore:
            pass
        else:
            raise ValueError('Implicit candidate .gitleaksignore was not rejected')
        (root / '.gitleaksignore').unlink()
        malicious = '[allowlist]\ndescription = "Untrusted candidate config"\nregexes = [".*"]\n'
        (root / '.gitleaks.toml').write_text(malicious)
        env = dict(os.environ, GITLEAKS_CONFIG=str(root / '.gitleaks.toml'),
                   GITLEAKS_CONFIG_TOML=malicious)
        attacked = scan(scanner, config, ignore, 'dir', root, report, env)
        if not any(item.get('RuleID') == 'github-pat' and item.get('File', '').endswith('credential.py')
                   for item in attacked):
            raise ValueError('Candidate ignore/config or environment concealed a generated credential')
    print('INLINE_COMMENT_IGNORE_FILE_AND_CONFIG_SUPPRESSION_REJECTED=PASS')


def verify_adjacent(scanner, config, ignore, repository, source):
    if repository != PUBLIC_REPOSITORY:
        return
    data = (source / PUBLIC_PATH).read_bytes()
    if not all(public_algorithm_bytes(data, line) for line in PUBLIC_LINES):
        raise ValueError('Reviewed public algorithm file changed')
    with tempfile.TemporaryDirectory() as fixture, tempfile.TemporaryDirectory() as reports:
        root = Path(fixture)
        target = root / PUBLIC_PATH
        target.parent.mkdir(parents=True)
        token = 'ghp_' + ''.join(secrets.SystemRandom().sample(string.ascii_letters + string.digits, 36))
        lines = data.splitlines(keepends=True)
        lines.insert(4593, ('api_key = "' + token + '" # gitleaks:allow\n').encode())
        target.write_bytes(b''.join(lines))
        findings = scan(scanner, config, ignore, 'dir', root, Path(reports) / 'adjacent.json')
        unknown = unapproved(findings, repository, 'dir', root)
        if not any(item.get('RuleID') == 'github-pat' and item.get('File') == PUBLIC_PATH
                   for item in unknown):
            raise ValueError('Adjacent generated credential was concealed')
    print('PUBLIC_ALGORITHM_ADJACENT_CREDENTIAL_REJECTED=PASS')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scanner', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--ignore-path', type=Path, required=True)
    parser.add_argument('--reports', type=Path, required=True)
    args = parser.parse_args()
    scanner, config, ignore = (value.resolve() for value in (args.scanner, args.config, args.ignore_path))
    args.reports.mkdir(parents=True, exist_ok=True)
    failed = False
    try:
        verify_controls(scanner, config, ignore)
        verify_adjacent(scanner, config, ignore, os.environ.get('GITHUB_REPOSITORY', ''), Path.cwd())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('SCANNER_CONTROL_REGRESSION=FAIL')
        failed = True
    for kind in ('git', 'dir'):
        try:
            findings = scan(scanner, config, ignore, kind, Path.cwd(), args.reports / (kind + '.json'))
            metadata = [{key: item.get(key) for key in
                         ('File', 'StartLine', 'EndLine', 'RuleID', 'Commit', 'Fingerprint')}
                        for item in findings]
            print(json.dumps({'scope': kind, 'finding_metadata': metadata}, sort_keys=True))
            unknown = unapproved(findings, os.environ.get('GITHUB_REPOSITORY', ''), kind, Path.cwd())
            print(kind.upper() + '_UNAPPROVED_FINDINGS=' + str(len(unknown)))
            failed |= bool(unknown)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            print(kind.upper() + '_SCANNER_EXECUTION=FAIL')
            failed = True
    if failed:
        raise SystemExit('Secret validation failed; no findings or scanner errors are waived')


if __name__ == '__main__':
    main()
