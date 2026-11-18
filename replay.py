"""Standalone replay of the disclosure-limited F1B source sets."""
import ast, hashlib, json, os, re, stat, subprocess, sys, tempfile
from pathlib import Path
WITNESS = 'tests/test_p18d_f1b_supervision.py'
PINS = {
 'app/outbox_worker.py': ('6C8F03FF475DAC725B13CA6672E577E46FE82BF063E8E8B767720032D3F7B843', 'D332DB4EB01929590F56A1E70558F11AB59CC18EB3DE538FB399B4DEB632D562'),
 'app/run_worker.py': ('2E453E3F31155AE074AB3426FD25E0826323829533F7948F1F3D53D6808BBA8C', '7C1B7F19AEAC2290AD9B01A4C7C4CFD136348881333C265CEB654BD9FDE3B230'),
 'app/postgres_identity.py': ('1D7CAB504A20C0A7A864948491C6FB107BF0F610036EAE1507EA5B6C44C9D042',)*2,
 'app/auth/provider_dispatch_gate.py': ('EE9F6C2DC61F9445DE44089982A4A89066BB61B7AE15D7DCD380226ABB255DD6',)*2,
 WITNESS: ('68DCBCE79B0041B8EAB00202B5C570156E05351750E7FA073BAA866DC7A151EE',)*2,
}
EXPECT = {
 'resource_fatal':(True,'DatabaseIdentityError',True),
 'resource_nominal':(True,'RuntimeError',True),
 'caller_nominal':(True,True,1,True,True,True),
 'caller_fatal':(True,True,1,True,True,True),
 'health_fatal':(False,True), 'health_cancelled':(False,True), 'health_prestart_cancel':(False,True),
 'wait_after_stop':(True,True), 'observer_cancel':(True,True,True),
 'concurrent_start':(True,True,1,1,True),
 'supervisor_fatal':(True,True,'DatabaseIdentityError'),
 'supervisor_cleanup_cancel':(True,True,'DatabaseIdentityError'),
 'supervisor_signal':(True,False,'NONE'),
 'supervisor_race':(True,True,'DatabaseIdentityError'),
}
RED_EXPECT = {
 'resource_fatal':(False,'CancelledError',True),
 'resource_nominal':(False,'CancelledError',True),
 'caller_nominal':(True,False,2,True,True,True),
 'caller_fatal':(True,False,2,True,True,True),
 'health_fatal':(None,True),'health_cancelled':(None,True),'health_prestart_cancel':(None,True),
 'wait_after_stop':(True,False),'supervisor_fatal':(False,True,'DatabaseIdentityError'),
 'supervisor_cleanup_cancel':(False,False,'CancelledError'),
}

def require(ok, reason):
    if not ok:
        raise SystemExit(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def safe_read(base, rel):
    p = base
    for component in Path(rel).parts:
        require(component not in ('..', '.', '') and not Path(component).is_absolute(), 'UNSAFE_PATH')
        p = p / component
        info = p.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'LINK_OR_REPARSE_PATH')
    require(p.is_file() and p.resolve().is_relative_to(base), 'NOT_REGULAR_LOCAL_FILE')
    require(p.stat().st_size <= 8*1024*1024, 'FILE_TOO_LARGE')
    return p.read_bytes()


def check_suite(text, baseline):
    expected = EXPECT | (RED_EXPECT if baseline else {})
    actual = {}
    for match in re.finditer(r'^(?:test_[a-z_]+ \([^\r\n]+\) \.\.\. )?L23_PROBE=([a-z_]+) (\([^\r\n]+\))[ \t]*$', text, re.M):
        name, raw = match.groups()
        require(name in expected and name not in actual, 'DUPLICATE_OR_UNKNOWN_PROBE')
        require(len(raw) < 512, 'PROBE_RESULT_TOO_LONG')
        actual[name] = ast.literal_eval(raw)
    require(actual.keys() == expected.keys(), 'PROBE_SET_MISMATCH')
    # Compare canonical representations (bool vs integer is significant).
    require(all(repr(actual[k]) == repr(v) for k,v in expected.items()), 'PROBE_OUTCOME_MISMATCH')
    require(len(re.findall(r'^Ran 14 tests? in ', text, re.M)) == 1, 'TEST_COUNT_MISMATCH')
    marker = 'L23_EXPECTED_RED_10_FAIL_4_PASS' if baseline else 'L23_GREEN_14_OF_14_PASS'
    require(text.splitlines().count(marker) == 1, 'SUITE_MARKER_MISMATCH')
    failures = re.findall(r'^FAIL: test_([a-z_]+)\b', text, re.M)
    require(len(failures)==(10 if baseline else 0) and set(failures)==(set(RED_EXPECT) if baseline else set()), 'FAILURE_SET_MISMATCH')
    require(not re.search(r'^ERROR:|^FAILED \(.*errors=', text, re.M), 'UNEXPECTED_SUITE_ERROR')
    if not baseline:
        require('Traceback (most recent call last)' not in text, 'UNEXPECTED_GREEN_TRACEBACK')
    require(re.search(r'^FAILED \(failures=10\)$' if baseline else r'^OK$', text, re.M), 'SUITE_SUMMARY_MISMATCH')
    return actual


def validate_run(name, code, text):
    if name in ('red', 'green'):
        require(code == 0, 'SUITE_EXIT_MISMATCH:'+name)
        return check_suite(text, name=='red')
    if name=='fatal':
        require(code==1 and text.splitlines().count('L23_CHILD_FATAL_IDENTITY_VERIFIED')==1 and 'L23_CHILD_GRACEFUL_EXIT' not in text and text.strip().splitlines()[-1]=='DatabaseIdentityError: synthetic fatal identity denial', 'FATAL_CHILD_MISMATCH')
    elif name=='graceful':
        require(code==0 and text.splitlines().count('L23_CHILD_GRACEFUL_EXIT')==1 and 'L23_CHILD_FATAL_IDENTITY_VERIFIED' not in text and 'Traceback (most recent call last)' not in text, 'GRACEFUL_CHILD_MISMATCH')
    else:
        raise SystemExit('UNEXPECTED_RUN')
    return {}



def main():
    require(sys.version_info >= (3, 10) and __debug__, 'UNSUPPORTED_PYTHON_OR_MODE')
    base=Path(__file__).resolve().parent
    manifest=json.loads(safe_read(base,'manifest.json'))
    require(manifest['original_commits']==['987559517e5bef00fcbe341360270781352a4362','2c8ebf86c7914f1bdb69dcd1f4410537748fbe57'],'PROVENANCE_LABEL_MISMATCH')
    rows={(r['snapshot'],r['path']):r for r in manifest['entries']}
    require(len(rows)==len(manifest['entries'])==10 and set(rows)=={(s,p) for s in ('red','green') for p in PINS},'MANIFEST_SCOPE_MISMATCH')
    sources={}
    for i,label in enumerate(('red','green')):
        for path,pins in PINS.items():
            data=safe_read(base,label+'/'+path); row=rows[label,path]
            oid=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            require(sha(data)==pins[i]==row['sha256'] and len(data)==row['bytes'] and oid==row['blob'],'SOURCE_IDENTITY_MISMATCH:'+path)
            sources[label,path]=data
    require(sources['red',WITNESS]==sources['green',WITNESS],'WITNESS_MISMATCH')
    print('ALL_10_SOURCE_PINS_VERIFIED',flush=True)
    print('Python:',sys.version.split()[0],flush=True)
    print('Synthetic I/O only; not an OS sandbox.',flush=True)
    out=Path(tempfile.mkdtemp(prefix='DQ_IV01_REPLAY_')).resolve()
    scratch=out/'scratch'; scratch.mkdir()
    for (label,path),data in sources.items():
        target=out/label/path; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
    env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','SYSTEMDRIVE'}}
    env.update(TEMP=str(scratch),TMP=str(scratch),TMPDIR=str(scratch))
    results=[]
    for name,label,args in [('red','red',['--expect-red-baseline']),('green','green',[]),('fatal','green',['--supervisor-child-fatal']),('graceful','green',['--supervisor-child-signal'])]:
        r=subprocess.run([sys.executable,'-I','-S','-B',str(out/label/WITNESS),*args],cwd=out/label,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
        (out/(name+'.log')).write_bytes(r.stdout)
        probes=validate_run(name,r.returncode,r.stdout.decode('utf-8','strict').replace('\r\n','\n'))
        results.append(dict(name=name,process_exit_code=r.returncode,probes=probes,log_sha256=sha(r.stdout)))
        print('REPLAY_'+name.upper()+'_PASS',flush=True)
    for (label,path),data in sources.items():
        require(safe_read(out,label+'/'+path)==data and safe_read(base,label+'/'+path)==data,'SOURCE_BYTES_CHANGED')
    result={'python':sys.version.split()[0],'platform':sys.platform,'runs':results,'scope':'focused synthetic supervision replay','original_commit_membership_independently_verified':False}
    (out/'replay-result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('RESULT_DIRECTORY:',out)
    print('FOCUSED_REPLAY_PASS')

if __name__=='__main__': main()
