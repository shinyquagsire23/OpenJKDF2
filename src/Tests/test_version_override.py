"""Portable CMake-P tests of the actual candidate; temporary Git fixtures only."""
from pathlib import Path
import argparse,os,shutil,subprocess,sys,tempfile,unittest
HERE=Path(__file__).resolve().parent
CMAKE=shutil.which('cmake')
GIT=shutil.which('git')
CANDIDATE=Path(__file__).resolve().parents[2]/'cmake_modules/version.cmake'
class VersionOverride(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='openjkdf2-version-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.env=os.environ.copy()
        for key in ('OPENJKDF2_RELEASE_COMMIT','OPENJKDF2_RELEASE_COMMIT_SHORT','GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE'):
            self.env.pop(key,None)
        self.env.update(GIT_AUTHOR_NAME='Synthetic Test Fixture',GIT_AUTHOR_EMAIL='fixture@example.invalid',GIT_COMMITTER_NAME='Synthetic Test Fixture',GIT_COMMITTER_EMAIL='fixture@example.invalid')
        self.git('init','-q')
        tree=self.git('hash-object','-t','tree','-w','--stdin',data=b'').strip()
        self.commit=self.git('commit-tree',tree,'-m','synthetic fixture').strip()
        self.git('update-ref','HEAD',self.commit)
        self.short=self.git('rev-parse','--short=8','HEAD').strip()
    def git(self,*args,data=None):
        return subprocess.check_output([GIT,*args],cwd=self.root,env=self.env,input=data).decode()
    def run_case(self,overrides):
        resultfile=self.root/'result.txt'
        script=self.root/'case.cmake'
        script.write_text('include("'+CANDIDATE.as_posix()+'")\nfile(WRITE "'+resultfile.as_posix()+'" "${OPENJKDF2_RELEASE_COMMIT}\\n${OPENJKDF2_RELEASE_COMMIT_SHORT}\\n")\n')
        result=subprocess.run([CMAKE,'-P',str(script)],cwd=self.root,env={**self.env,**overrides},capture_output=True,text=True)
        return result,resultfile.read_text().splitlines() if resultfile.exists() else None
    def test_absent_override_preserves_original_git_behavior(self):
        new,new_values=self.run_case({})
        self.assertEqual(new.returncode,0,new.stderr)
        self.assertEqual(new_values,[self.commit,self.short])
    def test_valid_override_wins_over_different_git_checkout(self):
        full='0123456789abcdef'*2+'01234567'
        for short in (full[:8],full[:12],full):
            with self.subTest(short=short):
                result,values=self.run_case({'OPENJKDF2_RELEASE_COMMIT':full,'OPENJKDF2_RELEASE_COMMIT_SHORT':short})
                self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(values,[full,short]);self.assertNotEqual(full,self.commit)
    def test_uppercase_hex_is_normalized(self):
        full='ABCDEF0123456789'*2+'ABCDEF01'
        result,values=self.run_case({'OPENJKDF2_RELEASE_COMMIT':full,'OPENJKDF2_RELEASE_COMMIT_SHORT':full[:8].lower()})
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(values,[full.lower(),full[:8].lower()])
    def test_invalid_overrides_fail_closed(self):
        good='0123456789abcdef'*2+'01234567'
        cases=[{}, {'OPENJKDF2_RELEASE_COMMIT_SHORT':good[:8]}, {'OPENJKDF2_RELEASE_COMMIT':good}, {'OPENJKDF2_RELEASE_COMMIT':'','OPENJKDF2_RELEASE_COMMIT_SHORT':''}]
        cases=cases[1:]
        for bad in (good[:-1],good+'0','g'+good[1:],good+'\n',' '+good,good[:10]+';'+good[11:]):
            cases.append({'OPENJKDF2_RELEASE_COMMIT':bad,'OPENJKDF2_RELEASE_COMMIT_SHORT':good[:8]})
        for short in ('',good[:7],good+'0','aaaaaaaa','0123456g',good[:8]+'\n',' '+good[:8]):
            cases.append({'OPENJKDF2_RELEASE_COMMIT':good,'OPENJKDF2_RELEASE_COMMIT_SHORT':short})
        for value in cases:
            with self.subTest(value=value):
                result,_=self.run_case(value)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('Release commit',result.stderr)
    def test_override_requires_no_git_checkout(self):
        with tempfile.TemporaryDirectory(prefix='openjkdf2-version-no-git-') as directory:
            self.root=Path(directory)
            full='1'*40
            result,values=self.run_case({'OPENJKDF2_RELEASE_COMMIT':full,'OPENJKDF2_RELEASE_COMMIT_SHORT':full[:8]})
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(values,[full,full[:8]])
if __name__=='__main__':
    if not CMAKE or not GIT:
        sys.exit('ERROR: cmake and git are required; no tests were run')
    parser=argparse.ArgumentParser();parser.add_argument('--candidate',type=Path,default=CANDIDATE)
    options,remaining=parser.parse_known_args();CANDIDATE=options.candidate.resolve()
    unittest.main(argv=[sys.argv[0],*remaining],verbosity=2)
