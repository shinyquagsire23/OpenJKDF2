"""Synthetic regression fixtures for allocation/slot safety; no retail data."""
import unittest
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from key_domain_guard import (analyze_key_bytes, plan_detail_nodes, keys_from_pup,
                              validate_hierarchy, load_json, write_report)

ROOT = Path(__file__).parent

class KeyDomainGuardTests(unittest.TestCase):
    def test_18_node_model_with_19_slot_animation_reserves_leaf(self):
        footprint=analyze_key_bytes({'run.key':b'JOINTS 18\nNODE 0\nNODE 17\n','saber.key':b'JOINTS 19\nNODE 18\n'})
        plan=plan_detail_nodes(18,footprint,40)
        self.assertEqual(plan['reserved_invisible_leaf_indices'],[18])
        self.assertEqual(plan['first_detail_index'],19)
        self.assertEqual(plan['total_node_count'],59)
        self.assertNotIn(18,plan['detail_indices'])
    def test_sparse_domain_still_reserves_declared_slots(self):
        footprint=analyze_key_bytes({'sparse.key':b'JOINTS 32\nNODES 2\nNODE 0\nNODE 31\n'})
        self.assertEqual(plan_detail_nodes(18,footprint,1)['first_detail_index'],32)
    def test_current_animation_cache_cannot_overflow(self):
        footprint=analyze_key_bytes({'full.key':b'JOINTS 64\nNODE 63\n'})
        with self.assertRaises(ValueError):plan_detail_nodes(18,footprint,1)
    def test_malformed_allocated_domain_rejected(self):
        with self.assertRaises(ValueError):analyze_key_bytes({'invalid.key':b'JOINTS 18\nNODE 18\n'})
    def test_comments_are_not_index_declarations(self):
        footprint=analyze_key_bytes({'comments.key':b'# JOINTS 99\nJOINTS 18 # harmless\n# NODE 18\nNODE 0\n'})
        self.assertEqual(footprint['required_slot_count'],18)
    def test_empty_or_duplicate_node_inputs_rejected(self):
        with self.assertRaises(ValueError):analyze_key_bytes({})
        with self.assertRaises(ValueError):analyze_key_bytes({'duplicate.key':b'JOINTS 18\nNODE 0\nNODE 0\n'})

    def test_malformed_keyword_lines_cannot_be_silently_skipped(self):
        for bad in [b'NODE -1', b'NODE junk', b'NODE:18', b'JOINTS junk', b'NODES -1']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                analyze_key_bytes({'bad.key':b'JOINTS 19\nNODE 0\n' + bad + b'\n'})

    def test_declared_nodes_count_must_match(self):
        with self.assertRaises(ValueError):
            analyze_key_bytes({'bad.key':b'JOINTS 19\nNODES 2\nNODE 0\n'})

    def test_absent_or_oversized_allocations_rejected(self):
        for data in [b'NODE 0', b'JOINTS 0\nNODE 0', b'JOINTS 65\nNODE 0', b'JOINTS 19']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                analyze_key_bytes({'bad.key':data})

    def test_binary_input_rejected(self):
        with self.assertRaises(ValueError):
            analyze_key_bytes({'bad.key':b'JOINTS 19\nNODE 0\x00'})

    def test_bool_and_noninteger_planning_inputs_rejected(self):
        fp={'required_slot_count':19}
        for base, chunks, limit in [(True,1,64),(18,True,64),(18,1,65),(18,1.5,64),(-1,1,64)]:
            with self.subTest(values=(base,chunks,limit)), self.assertRaises(ValueError):
                plan_detail_nodes(base,fp,chunks,limit)


class HierarchyGuardTests(unittest.TestCase):
    def setUp(self):
        self.fp=analyze_key_bytes({'synthetic.key':b'JOINTS 19\nNODE 18\n'})
        self.fixed=load_json((ROOT/'examples'/'fixed-19.json').read_bytes())

    def test_naive_slot_18_fails_fixed_slot_19_passes(self):
        naive=load_json((ROOT/'examples'/'naive-18.json').read_bytes())
        result=validate_hierarchy(naive,18,self.fp)
        self.assertFalse(result['valid'])
        self.assertTrue(any('node 18:' in error for error in result['errors']))
        self.assertTrue(validate_hierarchy(self.fixed,18,self.fp)['valid'])

    def test_reserved_slot_cannot_have_visible_descendants(self):
        self.fixed['nodes'][19]['parent']=18
        result=validate_hierarchy(self.fixed,18,self.fp)
        self.assertFalse(result['valid'])
        self.assertTrue(any('must be a leaf' in error for error in result['errors']))

    def test_neutral_detail_transform_required(self):
        self.fixed['nodes'][19]['neutral_transform']=False
        self.assertFalse(validate_hierarchy(self.fixed,18,self.fp)['valid'])

    def test_cycles_rejected_without_hanging(self):
        self.fixed['nodes'][1]['parent']=2
        self.fixed['nodes'][2]['parent']=1
        self.assertFalse(validate_hierarchy(self.fixed,18,self.fp)['valid'])

    def test_missing_parent_and_noncontiguous_indices_rejected(self):
        for field,value in [('parent',99),('index',20)]:
            doc=copy.deepcopy(self.fixed)
            doc['nodes'][19][field]=value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_hierarchy(doc,18,self.fp)

    def test_each_mesh_limit_is_inclusive_and_enforced(self):
        limits={'vertex_count':512,'uv_count':768,'face_count':512}
        self.fixed['meshes'][0].update(limits)
        self.assertTrue(validate_hierarchy(self.fixed,18,self.fp)['valid'])
        for field,limit in limits.items():
            doc=copy.deepcopy(self.fixed)
            doc['meshes'][0][field]=limit+1
            with self.subTest(field=field):
                self.assertFalse(validate_hierarchy(doc,18,self.fp)['valid'])

    def test_mesh_types_and_triangle_declaration(self):
        for value in [True,-1,1.5,'12']:
            doc=copy.deepcopy(self.fixed)
            doc['meshes'][0]['face_count']=value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_hierarchy(doc,18,self.fp)
        self.fixed['meshes'][0]['primitive']='quads'
        self.assertFalse(validate_hierarchy(self.fixed,18,self.fp)['valid'])

    def test_duplicate_mesh_ids_and_json_properties_rejected(self):
        self.fixed['meshes'].append(copy.deepcopy(self.fixed['meshes'][0]))
        with self.assertRaises(ValueError):validate_hierarchy(self.fixed,18,self.fp)
        with self.assertRaises(ValueError):load_json(b'{"nodes":[],"nodes":[]}')
        with self.assertRaises(ValueError):load_json(b'{"value":NaN}')


class InputAndCliTests(unittest.TestCase):
    def test_pup_resolves_all_modes_case_insensitively(self):
        keys=keys_from_pup(ROOT/'examples'/'synthetic.pup',ROOT/'examples'/'keys')
        self.assertEqual({p.name for p in keys},{'synthetic-base.key','synthetic-extra-slot.key'})
        with tempfile.TemporaryDirectory() as folder:
            d=Path(folder)
            (d/'UPPER.KEY').write_bytes(b'JOINTS 1\nNODE 0')
            (d/'test.pup').write_text('mode=0\nstand upper.key 0x00 0 0\n',encoding='utf-8')
            self.assertEqual(keys_from_pup(d/'test.pup',d),[(d/'UPPER.KEY').resolve()])

    def test_pup_missing_reference_traversal_and_bad_rows_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            d=Path(folder)
            for row in ['stand absent.key 0x00 0 0','stand ../outside.key 0x00 0 0',
                        'stand /outside.key 0x00 0 0','stand x.key BAD 0 0','stand x.key']:
                (d/'bad.pup').write_text('mode=0\n'+row+'\n',encoding='utf-8')
                with self.subTest(row=row), self.assertRaises(ValueError):
                    keys_from_pup(d/'bad.pup',d)

    def test_report_cannot_replace_an_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'input.key'
            original=b'JOINTS 19\nNODE 18\n'
            path.write_bytes(original)
            with self.assertRaises(ValueError):write_report(path,'{}\n',[path])
            self.assertEqual(path.read_bytes(),original)
            output=Path(folder)/'report.json'
            write_report(output,'{}\n',[path])
            self.assertEqual(output.read_bytes(),b'{}\n')
            self.assertEqual(list(Path(folder).glob('.key-domain-*.tmp')),[])

    def test_cli_exit_codes_report_and_no_absolute_input_paths(self):
        common=[sys.executable,'-B',str(ROOT/'key_domain_guard.py'),
                '--pup','examples/synthetic.pup','--key-dir','examples/keys',
                '--base-nodes','18','--detail-chunks','1','--hierarchy']
        for file,code in [('naive-18.json',1),('fixed-19.json',0)]:
            result=subprocess.run(common+['examples/'+file],cwd=ROOT,capture_output=True,text=True)
            with self.subTest(file=file):
                self.assertEqual(result.returncode,code,result.stderr)
                report=json.loads(result.stdout)
                self.assertEqual(report['plan']['first_detail_index'],19)
                self.assertNotIn(str(ROOT.resolve()),result.stdout)
        bad=subprocess.run([sys.executable,'-B',str(ROOT/'key_domain_guard.py'),
                            '--pup','examples/synthetic.pup','--base-nodes','18'],
                           cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(bad.returncode,2)
        self.assertIn('--pup and --key-dir',bad.stderr)

if __name__=='__main__':unittest.main()
