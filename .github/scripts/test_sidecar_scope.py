import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import validate_sidecar_scope as scope
import scan_sidecar_secrets as secret_scan


def row(oid='a' * 40, mode='100644', kind='blob'):
    return {'mode': mode, 'kind': kind, 'oid': oid}


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.repository = 'appolon1908/Blender'
        self.baseline = {
            scope.OWNED_SOURCE: row(), 'source/native.cpp': row('b' * 40),
            'COPYING': row('c' * 40), '.github/workflows/original.yml': row('d' * 40),
        }
        self.entries = {**self.baseline, **{name: row('e' * 40) for name in scope.CI_FILES}}
        self.manifest = scope.expected_manifest(self.repository)

    def validate(self):
        return scope.validate_entries(self.entries, self.baseline, self.manifest, self.repository)

    def test_owned_source_blob_can_change_but_complete_baseline_is_retained(self):
        self.entries[scope.OWNED_SOURCE] = row('f' * 40)
        self.assertEqual([], self.validate())

    def test_every_frozen_path_change_mode_or_removal_is_rejected(self):
        for name in set(self.baseline) - {scope.OWNED_SOURCE}:
            original = self.entries[name]
            for value in (None, row('f' * 40), row(mode='100755'), row(mode='120000')):
                with self.subTest(name=name, value=value):
                    if value is None:
                        self.entries.pop(name)
                    else:
                        self.entries[name] = value
                    self.assertTrue(self.validate())
                    self.entries[name] = original

    def test_new_application_native_documentation_and_authority_files_fail_closed(self):
        for name in ('codestra_api/extra.py', 'source/extra.cpp', 'docs/new.md',
                     '.github/workflows/extra.yml', 'AGENTS.md', '.gitignore'):
            self.entries[name] = row()
            self.assertTrue(self.validate(), name)
            self.entries.pop(name)

    def test_every_required_ci_artifact_and_owned_source_must_be_present_and_safe(self):
        for name in scope.CI_FILES | {scope.OWNED_SOURCE}:
            original = self.entries[name]
            for value in (None, row(mode='100755'), row(mode='120000'), row(mode='160000', kind='commit')):
                with self.subTest(name=name, value=value):
                    if value is None:
                        self.entries.pop(name)
                    else:
                        self.entries[name] = value
                    self.assertTrue(self.validate())
                    self.entries[name] = original

    def test_manifest_cannot_expand_scope_remove_baseline_or_assert_certification(self):
        for key, value in (('tested_sources', [scope.OWNED_SOURCE, 'source/native.cpp']),
                           ('reviewed_base_sha', 'f' * 40), ('native_engine_certified', True),
                           ('native_engine_certified', 0), ('schema_version', 1.0),
                           ('repository', 'unreviewed/repository')):
            manifest = copy.deepcopy(self.manifest)
            manifest[key] = value
            self.assertTrue(scope.validate_entries(self.entries, self.baseline, manifest, self.repository))
        manifest = copy.deepcopy(self.manifest)
        manifest.pop('tested_sources')
        self.assertTrue(scope.validate_entries(self.entries, self.baseline, manifest, self.repository))

    def test_pinned_gitlink_is_frozen_not_initialized_or_reinterpreted(self):
        self.baseline['libs/native'] = row('1' * 40, '160000', 'commit')
        self.entries['libs/native'] = self.baseline['libs/native']
        self.assertEqual([], self.validate())
        self.entries['libs/native'] = row('2' * 40, '160000', 'commit')
        self.assertTrue(self.validate())

    def test_duplicate_json_authority_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            scope.read_json('{"repository":"first","repository":"second"}')

    def test_policy_is_source_only_and_preserves_other_protections(self):
        policy = scope.source_policy(self.repository)
        self.assertIs(policy['production_activation_authorized'], False)
        self.assertEqual('video-sidecar-source', policy['required_checks'][0]['context'])
        self.assertEqual(15368, policy['required_checks'][0]['integration_id'])
        self.assertIn('deployment_authority', policy['preserve'])
        self.assertIn('review_requirements', policy['preserve'])


class TrustedGitBaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repository = 'appolon1908/Blender'
        self.git('init', '-q')
        (self.root / 'codestra_api').mkdir()
        (self.root / scope.OWNED_SOURCE).write_text('VALUE = 1\n')
        (self.root / 'COPYING').write_text('Original license\n')
        self.git('add', '.')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.tree = self.git('rev-parse', 'HEAD^{tree}').strip()
        self.profile_patch = patch.dict(scope.PROFILES, {self.repository: {
            'base': self.base, 'tree': self.tree, 'gitlinks': {},
        }})
        self.profile_patch.start()
        self.addCleanup(self.profile_patch.stop)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True)

    def commit(self):
        self.git('-c', 'user.name=source-test', '-c', 'user.email=source-test@example.invalid',
                 'commit', '-qm', 'Source validation fixture')

    def test_bootstrap_requires_exact_event_base_and_reviewed_tree(self):
        result = scope.trusted_manifest(self.root, self.repository, self.base, self.base)
        self.assertEqual(scope.expected_manifest(self.repository), result)
        self.assertIn('COPYING', scope.baseline_entries(self.root, self.repository))
        for base, bootstrap in (('', self.base), ('f' * 40, self.base), (self.base, 'f' * 40)):
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                scope.trusted_manifest(self.root, self.repository, base, bootstrap)
        with patch.dict(scope.PROFILES[self.repository], {'tree': 'f' * 40}):
            with self.assertRaises(ValueError):
                scope.baseline_entries(self.root, self.repository)

    def add_authority(self):
        (self.root / '.github').mkdir()
        (self.root / scope.MANIFEST).write_text(json.dumps(scope.expected_manifest(self.repository)))
        (self.root / '.github/checker.py').write_text('TRUSTED = True\n')
        (self.root / 'governance').mkdir()
        (self.root / scope.POLICY).write_text(json.dumps(scope.source_policy(self.repository)))
        self.git('add', '.')
        self.commit()
        return self.git('rev-parse', 'HEAD').strip()

    def test_existing_base_authority_allows_only_ordinary_owned_source_changes(self):
        event_base = self.add_authority()
        (self.root / scope.OWNED_SOURCE).write_text('VALUE = 2\n')
        self.assertEqual(scope.expected_manifest(self.repository),
                         scope.trusted_manifest(self.root, self.repository, event_base, self.base))

    def test_mutating_manifest_checker_policy_or_adding_ci_cannot_mirror_new_expectations(self):
        event_base = self.add_authority()
        for name in (scope.MANIFEST, '.github/checker.py', scope.POLICY, '.github/new.py'):
            path = self.root / name
            old = path.read_bytes() if path.exists() else None
            path.write_text('changed authority\n')
            self.git('add', name)
            with self.assertRaises(ValueError):
                scope.trusted_manifest(self.root, self.repository, event_base, self.base)
            self.git('reset', '-q', 'HEAD', '--', name)
            if old is None:
                path.unlink()
            else:
                path.write_bytes(old)

    def test_trusted_base_manifest_itself_cannot_introduce_unreviewed_source_paths(self):
        self.add_authority()
        manifest = scope.expected_manifest(self.repository)
        manifest['tested_sources'].append('unreviewed.py')
        (self.root / scope.MANIFEST).write_text(json.dumps(manifest))
        self.git('add', '.')
        self.commit()
        with self.assertRaises(ValueError):
            scope.trusted_manifest(self.root, self.repository, self.git('rev-parse', 'HEAD').strip(), self.base)


class ActualRepositoryTests(unittest.TestCase):
    def test_actual_registered_native_snapshot_and_gitlinks_are_pinned(self):
        repository = os.environ.get('GITHUB_REPOSITORY', 'appolon1908/' + Path.cwd().name)
        if repository not in scope.PROFILES:
            self.skipTest('Actual repository inventory is checked by both per-repository CI jobs')
        entries = scope.baseline_entries(Path.cwd(), repository)
        self.assertIn(scope.OWNED_SOURCE, entries)
        self.assertGreater(len(entries), 4000)
        self.assertEqual(scope.PROFILES[repository]['gitlinks'], {
            name: value['oid'] for name, value in entries.items() if value['kind'] == 'commit'
        })


class PublicAlgorithmTests(unittest.TestCase):
    def setUp(self):
        self.root = Path.cwd()
        self.data = (self.root / secret_scan.PUBLIC_PATH).read_bytes()

    def finding(self, kind, line):
        commit = secret_scan.PUBLIC_COMMIT if kind == 'git' else ''
        return {'File': secret_scan.PUBLIC_PATH, 'RuleID': 'generic-api-key',
                'StartLine': line, 'EndLine': line, 'Commit': commit,
                'Fingerprint': ((commit + ':') if commit else '') + secret_scan.PUBLIC_PATH
                               + ':generic-api-key:' + str(line)}

    def test_exact_four_public_identities(self):
        for kind in ('git', 'dir'):
            findings = [self.finding(kind, line) for line in secret_scan.PUBLIC_LINES]
            self.assertEqual([], secret_scan.unapproved(findings, secret_scan.PUBLIC_REPOSITORY, kind, self.root))

    def test_every_identity_tamper_and_duplicate_rejected(self):
        for kind in ('git', 'dir'):
            original = self.finding(kind, 4593)
            for field, changed in [('File', 'other.h'), ('RuleID', 'github-pat'),
                                   ('StartLine', 4594), ('StartLine', True), ('StartLine', '4593'),
                                   ('EndLine', 4594), ('Commit', 'a' * 40), ('Fingerprint', 'other')]:
                item = dict(original); item[field] = changed
                self.assertEqual([item], secret_scan.unapproved([item], secret_scan.PUBLIC_REPOSITORY, kind, self.root))
            self.assertEqual([original], secret_scan.unapproved([original], 'appolon1908/Natron', kind, self.root))
            self.assertEqual([original], secret_scan.unapproved([original, original], secret_scan.PUBLIC_REPOSITORY, kind, self.root))

    def test_complete_file_and_line_proofs_fail_on_any_byte_change(self):
        self.assertTrue(secret_scan.public_algorithm_bytes(self.data, 4593))
        self.assertFalse(secret_scan.public_algorithm_bytes(self.data + b'\n', 4593))
        lines = self.data.splitlines(keepends=True)
        lines[4592] = b'altered\n'
        self.assertFalse(secret_scan.public_algorithm_bytes(b''.join(lines), 4593))
        self.assertFalse(secret_scan.public_algorithm_bytes(self.data, 4594))

    def test_changed_effective_file_and_historical_blob_are_unknown(self):
        item = self.finding('git', 4593)
        with patch.object(secret_scan.subprocess, 'check_output', return_value=self.data + b'\n'):
            self.assertEqual([item], secret_scan.unapproved([item], secret_scan.PUBLIC_REPOSITORY, 'git', self.root))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); target = root / secret_scan.PUBLIC_PATH
            target.parent.mkdir(parents=True); target.write_bytes(self.data + b'\n')
            item = self.finding('dir', 4593)
            self.assertEqual([item], secret_scan.unapproved([item], secret_scan.PUBLIC_REPOSITORY, 'dir', root))


if __name__ == '__main__':
    unittest.main()
