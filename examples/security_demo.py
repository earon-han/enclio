#!/usr/bin/env python3
"""Run finite, observable Enclio policy examples as an ordinary Linux user."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--enclio', default='build/enclio')
    parser.add_argument('--cgroup-parent', default=os.getenv('ENCLIO_CGROUP_PARENT'))
    parser.add_argument('--output', type=Path, help='new directory; existing directories are rejected')
    args = parser.parse_args()
    if not args.cgroup_parent:
        parser.error('provide an already delegated cgroup v2 parent with --cgroup-parent or ENCLIO_CGROUP_PARENT')
    if os.getuid() == 0:
        parser.error('run as an ordinary user, inside an already delegated test/service scope')
    binary = shutil.which(args.enclio)
    if not binary:
        parser.error('cannot find the enclio binary')
    binary = str(Path(binary).resolve())
    parent = str(Path(args.cgroup_parent).resolve(strict=True))
    if args.output:
        root = args.output.resolve()
        if root.exists(): parser.error('--output must be a new directory to preserve prior results')
        root.mkdir(parents=True, mode=0o700)
    else:
        root = Path(tempfile.mkdtemp(prefix='enclio-security-demo-'))
    if ':' in str(root): parser.error('demo directory cannot contain a colon (mount syntax delimiter)')
    workspace = root/'workspace'; inputs=root/'inputs'; outputs=root/'outputs'; export=root/'export'; reports=root/'reports'
    for p in (workspace, inputs, outputs, export, reports): p.mkdir(mode=0o700)
    (inputs/'message.txt').write_text('READ_ONLY_INPUT\n')
    secret = root/'private-secret.txt'; secret.write_text('DEMO_ONLY_SECRET\n')
    payload = Path(__file__).with_name('security_probe.c')
    subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',str(payload),'-o',str(workspace/'demo-probe')],check=True)
    print('Demo files and results: '+str(root),flush=True)
    results=[]
    def limits(memory=134217728,pids=64):
        return ['--cgroup-parent',parent,'--memory-bytes',str(memory),'--pids-max',str(pids),'--cpu-percent','50','--seccomp','strict']
    def case(name,options,mode,expected=0,status='exited',reason=None,checks=()):
        report=reports/(name+'.json')
        command=[binary,'run','--workspace',str(workspace),'--result',str(report),*options,'--','/workspace/demo-probe',mode]
        if mode=='check': command.append(str(secret))
        (reports/(name+'.command.json')).write_text(json.dumps(command,indent=2)+'\n')
        print('\n$ '+shlex.join(command),flush=True)
        environment=os.environ.copy();environment['ENCLIO_DEMO_PRIVATE']='demo-host-value'
        q=subprocess.run(command,capture_output=True,timeout=65,env=environment)
        (reports/(name+'.stdout')).write_bytes(q.stdout);(reports/(name+'.stderr')).write_bytes(q.stderr)
        data=json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
        stdout=q.stdout.decode(errors='replace')
        good=(q.returncode==expected and data.get('status')==status and data.get('command_started') is True and
              data.get('cleanup_complete') is True and 'PROBE_EXECUTED' in stdout and
              data.get('resources',{}).get('cgroup_enforced') is True and all('PASS '+c in stdout for c in checks))
        if reason: good=good and data.get('limit_reason')==reason
        if name=='policy':
            good=good and (outputs/'result.txt').is_file() and (outputs/'result.txt').read_text()=='AUTHORIZED_OUTPUT\n' and (inputs/'message.txt').read_text()=='READ_ONLY_INPUT\n' and data['resources'].get('rlimits_applied') is True
        if name=='managed_disk': good=good and (export/'answer.txt').is_file() and (export/'answer.txt').read_text()=='EXPORT_OK\n' and not (workspace/'answer.txt').exists()
        if reason=='memory': good=good and data['resources'].get('oom_kills',0)>0
        if reason=='pids': good=good and data['resources'].get('pids_max_events',0)>0
        if reason=='output': good=good and len(q.stdout)+len(q.stderr)<=1024 and data.get('output_bytes',1025)<=1024
        results.append(dict(name=name,status='PASS' if good else 'FAIL',returncode=q.returncode,result=data))
        # Keep output-flood bytes in the evidence file, not in the terminal.
        if name!='output':print(stdout,end='',flush=True)
        print(('PASS' if good else 'FAIL')+': '+name+'; status='+str(data.get('status'))+'; limit_reason='+str(data.get('limit_reason')),flush=True)
        return good
    okay=case('policy',limits()+['--workspace-mode','readonly','--mount-ro',str(inputs)+':/data/input','--mount-rw',str(outputs)+':/data/output',
        '--network','isolated','--allow','example.com:443','--syscall','getppid=errno:42','--env','DEMO_MESSAGE=hello-from-caller',
        '--tmp-bytes','33554432','--cpu-seconds','5','--address-space-bytes','268435456','--file-bytes','65536','--open-files','64',
        '--timeout','40','--output-bytes','8192'],'check',checks=('READ_AUTHORIZED_INPUT','READONLY_WRITE_DENIED_EROFS','WRITE_AUTHORIZED_OUTPUT',
        'UNMOUNTED_HOST_SECRET_HIDDEN','ENVIRONMENT_ALLOWLIST','CUSTOM_GETPPID_ERRNO_42','ADDRESS_SPACE_LIMIT_256MIB',
        'PER_PROCESS_CPU_LIMIT_5_SECONDS','OPEN_FILES_LIMIT_EMFILE','FILE_SIZE_LIMIT_EFBIG','UNLISTED_HOST_HTTP_403','DIRECT_IP_HAS_NO_ROUTE','ALLOWED_HTTPS_FETCH_SUCCEEDED'))
    okay=case('managed_disk',limits()+['--workspace-mode','tmpfs','--disk-bytes','8388608','--export',str(export),'--network','none','--timeout','10','--output-bytes','8192'],'disk',checks=('SHARED_TMPFS_QUOTA_ENOSPC',)) and okay
    okay=case('pids',limits(pids=16)+['--workspace-mode','readonly','--network','none','--timeout','5','--output-bytes','8192'],'pids',126,'resource_limit','pids',('AGGREGATE_PIDS_LIMIT_EAGAIN',)) and okay
    okay=case('memory',limits(memory=33554432)+['--workspace-mode','readonly','--network','none','--timeout','5','--output-bytes','8192'],'memory',126,'resource_limit','memory') and okay
    okay=case('timeout',limits()+['--workspace-mode','readonly','--network','none','--timeout','1','--output-bytes','8192'],'timeout',124,'timeout') and okay
    okay=case('output',limits()+['--workspace-mode','readonly','--network','none','--timeout','5','--output-bytes','1024'],'output',126,'resource_limit','output') and okay
    summary=dict(binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
        example_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),probe_sha256=hashlib.sha256(payload.read_bytes()).hexdigest(),
        results=results,all_passed=bool(okay),automatic_retries=0)
    (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print('\n'+('All 6 scenarios passed.' if okay else 'Demo FAILED; see raw reports. Allowed HTTPS failures are not policy passes.'),flush=True)
    print('Results: '+str(root/'summary.json'),flush=True)
    return 0 if okay else 1


if __name__=='__main__':raise SystemExit(main())
