import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from set_mpc_model import prepare, update

class ProfileTests(unittest.TestCase):
    def fixture(self, newline=b'\r\n', mots=False):
        rows = [b'version 1', b'model: ky.3do', b'soundclass: ky.snd',
                b'sidemat: sabergreen0.mat', b'tipmat: sabergreen1.mat']
        if mots:
            rows.append(b'personality: 4')
        rows += [b'', b'forcepowers:', b'bin: 23 value: 3.000000',
                 b'spendable stars: 1.000000', b'# retained comment \xe9']
        return newline.join(rows) + newline

    def test_only_model_bytes_change_for_both_games_and_newlines(self):
        for mots in (False, True):
            for nl in (b'\n', b'\r\n'):
                data = self.fixture(nl, mots)
                changed, old = prepare(data, 'custom.3do')
                self.assertEqual(old, 'ky.3do')
                self.assertEqual(changed, data.replace(b'model: ky.3do', b'model: custom.3do'))

    def test_bad_inputs_rejected(self):
        for name in ('../escape.3do', 'dir/face.3do', 'x\nmodel: foo.3do', 'a'*28+'.3do', 'f\u00e9.3do'):
            with self.assertRaises(ValueError): prepare(self.fixture(), name)
        for data in (b'version 2\nmodel: ky.3do\n', b'version 1\n', self.fixture()+b'model: kk.3do\n'):
            with self.assertRaises(ValueError): prepare(data, 'custom.3do')

    def test_preview_backup_write_and_idempotence(self):
        with tempfile.TemporaryDirectory(prefix='mpc-selection-test-') as td:
            p = Path(td)/'synthetic.mpc'
            original = self.fixture(mots=True)
            p.write_bytes(original)
            self.assertFalse(update(p, 'custom.3do')['applied'])
            self.assertEqual(p.read_bytes(), original)
            receipt = update(p, 'custom.3do', True)
            self.assertTrue(receipt['applied'])
            self.assertEqual(Path(receipt['backup']).read_bytes(), original)
            self.assertEqual(p.read_bytes(), original.replace(b'model: ky.3do', b'model: custom.3do'))
            self.assertFalse(update(p, 'custom.3do', True)['changed'])
            self.assertEqual(len(list(Path(td).glob('*.bak'))), 1)
            bad = Path(td)/'player.plr'; bad.write_bytes(original)
            with self.assertRaises(ValueError): update(bad, 'custom.3do', True)
            self.assertEqual(bad.read_bytes(), original)

    def test_ambiguous_or_malformed_version_rejected(self):
        for version in (b'version 1\nversion 2', b'version 1\nversion 1',
                        b'version\n1', b'version -1', b'version: 1'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                prepare(self.fixture().replace(b'version 1', version), 'custom.3do')

    def test_final_and_ancestor_links_rejected_without_native_link_privilege(self):
        with tempfile.TemporaryDirectory(prefix='mpc-selection-test-') as td:
            p = Path(td) / 'synthetic.mpc'
            original = self.fixture()
            p.write_bytes(original)
            real_lstat = Path.lstat
            for linked in (p, p.parent):
                for mode, attributes in ((stat.S_IFLNK, 0), (stat.S_IFREG, 0x400)):
                    def fake_lstat(path, **kwargs):
                        if path == linked:
                            return SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
                        return real_lstat(path, **kwargs)
                    with self.subTest(linked=linked, attributes=attributes):
                        with mock.patch.object(Path, 'lstat', autospec=True, side_effect=fake_lstat):
                            with self.assertRaisesRegex(ValueError, 'links or reparse'):
                                update(p, 'custom.3do', True)
            self.assertEqual(p.read_bytes(), original)
            self.assertFalse(list(p.parent.glob('*.bak')))

    def test_hardlinked_profile_rejected(self):
        with tempfile.TemporaryDirectory(prefix='mpc-selection-test-') as td:
            p = Path(td) / 'synthetic.mpc'
            p.write_bytes(self.fixture())
            alias = Path(td) / 'alias.mpc'
            try:
                os.link(p, alias)
            except OSError as exc:
                self.skipTest(f'Filesystem cannot create a hard link: {exc}')
            with self.assertRaisesRegex(ValueError, 'exactly one hard link'):
                update(alias, 'custom.3do', True)
            self.assertEqual(p.read_bytes(), self.fixture())
            self.assertFalse(list(p.parent.glob('*.bak')))

    def test_failed_backup_verification_never_writes_profile(self):
        with tempfile.TemporaryDirectory(prefix='mpc-selection-test-') as td:
            p = Path(td) / 'synthetic.mpc'
            original = self.fixture()
            p.write_bytes(original)
            real_read = Path.read_bytes
            def bad_backup(path):
                return b'corrupted backup' if path.suffix == '.bak' else real_read(path)
            with mock.patch.object(Path, 'read_bytes', autospec=True, side_effect=bad_backup):
                with self.assertRaisesRegex(RuntimeError, 'Backup verification failed'):
                    update(p, 'custom.3do', True)
            self.assertEqual(p.read_bytes(), original)

    def test_intervening_profile_save_is_not_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='mpc-selection-test-') as td:
            p = Path(td) / 'synthetic.mpc'
            original = self.fixture()
            p.write_bytes(original)
            external_save = original.replace(b'spendable stars: 1.', b'spendable stars: 2.')
            real_read = Path.read_bytes
            reads = 0
            def intervening_save(path):
                nonlocal reads
                if path == p:
                    reads += 1
                    if reads == 2:
                        p.write_bytes(external_save)
                return real_read(path)
            with mock.patch.object(Path, 'read_bytes', autospec=True, side_effect=intervening_save):
                with self.assertRaisesRegex(RuntimeError, 'Profile changed while preparing'):
                    update(p, 'custom.3do', True)
            self.assertEqual(p.read_bytes(), external_save)
            backups = list(p.parent.glob('*.bak'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)

    def test_cli_requires_explicit_apply(self):
        with tempfile.TemporaryDirectory(prefix='mpc-selection-test-') as td:
            p = Path(td) / 'synthetic.mpc'
            original = self.fixture()
            p.write_bytes(original)
            result = subprocess.run(
                [sys.executable, '-B', str(Path(__file__).with_name('set_mpc_model.py')),
                 str(p), 'custom.3do'], capture_output=True, text=True, check=True)
            self.assertFalse(json.loads(result.stdout)['applied'])
            self.assertEqual(p.read_bytes(), original)
            self.assertFalse(list(p.parent.glob('*.bak')))

if __name__ == '__main__': unittest.main(verbosity=2)
