"""Synthetic text fixtures only: no game models or other art assets."""
from pathlib import Path
import tempfile
import unittest
from texture_mode import convert, write_copy


def fixture(newline='\r\n'):
    # Deliberately minimal field-scanner fixture, not a playable mesh.
    return newline.join(['# modes should preserve comments TEXTUREMODE 0',
        'SECTION: HEADER', '3DO 2.1', 'SECTION: GEOMETRYDEF', 'GEOSETS 2',
        'GEOSET 0', 'MESHES 1', 'MESH 0', 'NAME synthetic', ' TEXTUREMODE 0 # keep',
        'FACES 2', '0: 0 0x0001 4 3 0 0.0000 3 0,0 1,1 2,2',
        '1: 0 0x0000 4 3 1 0.2500 3 0,0 2,2 3,3', 'FACE NORMALS',
        '0: 0.0 0.0 1.0', '1: 0.0 0.0 1.0', 'GEOSET 1', 'MESHES 1',
        'MESH 0', 'NAME synthetic', 'TEXTUREMODE 3', 'FACES 1',
        '0: 0 0x0001 4 3 2 0.0000 3 0,0 1,1 2,2',
        'FACE NORMALS', '0: 0.0 0.0 1.0', 'SECTION: HIERARCHYDEF',
        'HIERARCHY NODES 1', '# an untouched hierarchy block', '']).encode('ascii')


class TextureModeTests(unittest.TestCase):
    def test_report_does_not_change_bytes(self):
        source = fixture()
        output, report = convert(source)
        self.assertEqual(output, source)
        self.assertEqual(report['mesh_modes'], {0: 1, 3: 1})
        self.assertEqual(report['face_modes'], {0: 1, 1: 1, 2: 1})

    def test_all_geosets_and_both_mode_levels(self):
        source = fixture()
        output, report = convert(source, 1)
        self.assertEqual(report['changed_token_count'], 4)
        self.assertEqual(output.count(b'\r\n'), source.count(b'\r\n'))
        self.assertIn(b'# modes should preserve comments TEXTUREMODE 0', output)
        self.assertIn(b'1: 0 0x0000 4 3 1 0.2500', output)
        self.assertEqual(output.split(b'SECTION: HIERARCHYDEF')[1], source.split(b'SECTION: HIERARCHYDEF')[1])
        _, after = convert(output)
        self.assertEqual(after['mesh_modes'], {1: 2})
        self.assertEqual(after['face_modes'], {1: 3})

    def test_zero_mode_is_explicit_and_idempotent(self):
        output, _ = convert(fixture('\n'), 0)
        repeated, report = convert(output, 0)
        self.assertEqual(output, repeated)
        self.assertEqual(report['changed_token_count'], 0)

    def test_truncated_face_table_is_rejected(self):
        with self.assertRaises(ValueError):
            convert(fixture().replace(b'FACES 2', b'FACES 3'), 1)

    def test_missing_mesh_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            convert(fixture().replace(b'TEXTUREMODE 3', b'TEXTUREMODE 7'), 1)

    def test_new_copy_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            source, output = Path(temp)/'in.3do', Path(temp)/'out.3do'
            data = fixture()
            source.write_bytes(data)
            report = write_copy(source, output, 1)
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(report['changed_token_count'], 4)
            with self.assertRaises(FileExistsError):
                write_copy(source, output, 1)
            with self.assertRaises(ValueError):
                write_copy(source, source, 1)


if __name__ == '__main__':
    unittest.main()
