#!/usr/bin/env python3
"""Finite CLI checks for explicit network, directory binds and syscall overrides."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile

PROBE = r'''#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
int main(int argc,char **argv){
 setvbuf(stdout,NULL,_IONBF,0); puts("PROBE_EXECUTED");
 if(argc!=2)return 2;
 if(!strcmp(argv[1],"parent")){errno=0;long n=syscall(SYS_getppid);printf("RETURN=%ld ERRNO=%d\n",n,errno);return 0;}
 if(!strcmp(argv[1],"selfread")){char src[]="SELF_READ",dst[sizeof(src)]={0};struct iovec a={dst,sizeof(dst)},b={src,sizeof(src)};errno=0;long n=syscall(SYS_process_vm_readv,getpid(),&a,1,&b,1,0);printf("RETURN=%ld ERRNO=%d DATA=%s\n",n,errno,dst);return 0;}
 return 2;
}'''


def main():
 p=argparse.ArgumentParser();p.add_argument('--binary',default='build/enclio');p.add_argument('--output',default='build/options-integration.json');a=p.parse_args()
 binary=str(Path(a.binary).resolve());results=[]
 def record(name,good,**extra):
  results.append(dict(name=name,status='PASS' if good else 'FAIL',**extra));print(results[-1]['status']+': '+name,flush=True)
 with tempfile.TemporaryDirectory(prefix='enclio-options-') as t:
  root=Path(t);workspace=root/'workspace';workspace.mkdir();source=root/'source';source.mkdir();(source/'data').write_text('MOUNT_INPUT');export=root/'export';export.mkdir()
  (workspace/'options_probe.c').write_text(PROBE)
  subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',str(workspace/'options_probe.c'),'-o',str(workspace/'options_probe')],check=True)
  subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','tests/probe.c','-o',str(workspace/'probe')],check=True)
  index=0
  def run(name,options,command,expected=0,status='exited',contains=()):
   nonlocal index
   index+=1;report=root/f'result-{index}.json'
   cmd=[binary,'run','--workspace',str(workspace),'--timeout','5','--result',str(report),*options,'--',*command]
   q=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
   d=json.loads(report.read_text()) if report.exists() and report.stat().st_size else {}
   good=q.returncode==expected and d.get('status')==status and d.get('command_started') is True and d.get('cleanup_complete') is True and 'PROBE_EXECUTED' in q.stdout and all(x in q.stdout for x in contains)
   record(name,good,returncode=q.returncode,stdout=q.stdout,stderr=q.stderr,result=d)
   return q,d
  def reject(name,options,result_path=None):
   cmd=[binary,'run','--workspace',str(workspace),*options]
   if result_path:cmd+=['--result',str(result_path)]
   q=subprocess.run([*cmd,'--','/bin/sh','-c','echo SHOULD_NOT_EXECUTE'],capture_output=True,text=True,timeout=10)
   record(name,q.returncode==2 and 'SHOULD_NOT_EXECUTE' not in q.stdout,returncode=q.returncode,stdout=q.stdout,stderr=q.stderr)
  # Netns equality and reachability are observed against a local harness peer,
  # independent of DNS/publicnetwork availability.
  host_namespace=os.readlink('/proc/self/ns/net')
  with socket.socket() as peer:
   peer.bind(('127.0.0.1',0));peer.listen(4);port=peer.getsockname()[1]
   script=f'''import os,socket
print("PROBE_EXECUTED",flush=True)
print("NETNS="+os.readlink("/proc/self/ns/net"),flush=True)
s=socket.socket();s.settimeout(1)
try:s.connect(("127.0.0.1",{port}));print("DIRECT_CONNECTED",flush=True)
except OSError:print("DIRECT_DENIED",flush=True)
print("AUTO_PROXY="+str(os.getenv("HTTP_PROXY")),flush=True)
'''
   for mode in ['none','host','isolated']:
    options=['--network',mode]+(['--allow-host','example.com'] if mode=='isolated' else [])
    q,d=run('network_'+mode,options,['/usr/bin/python3','-c',script],contains=('DIRECT_CONNECTED' if mode=='host' else 'DIRECT_DENIED', 'AUTO_PROXY=http://127.0.0.1:18080' if mode=='isolated' else 'AUTO_PROXY=None'))
    namespace=next((x[6:] for x in q.stdout.splitlines() if x.startswith('NETNS=')),None)
    record('network_'+mode+'_namespace',bool(namespace) and ((namespace==host_namespace)==(mode=='host')),payload_netns=namespace,parent_netns=host_namespace)
   run('network_default_none',[],['/usr/bin/python3','-c',script],contains=('DIRECT_DENIED','AUTO_PROXY=None'))
   run('network_legacy_allow_isolated',['--allow-host','example.com'],['/usr/bin/python3','-c',script],contains=('DIRECT_DENIED','AUTO_PROXY=http://127.0.0.1:18080'))
  run('host_dns_and_hosts_configuration',['--network','host'],['/usr/bin/python3','-c',"import socket; print('PROBE_EXECUTED',flush=True); assert socket.getaddrinfo('localhost',80); print('HOST_DNS_OK')"],contains=('HOST_DNS_OK',))
  reject('isolated_requires_policy',['--network','isolated'])
  reject('none_rejects_policy',['--network','none','--allow-host','example.com'])
  reject('host_rejects_policy',['--network','host','--allow-host','example.com'])
  reject('unknown_network_mode',['--network','invalid'])
  run('extra_readonly_mount',['--mount-ro',f'{source}:/data'],['/bin/sh','-c','echo PROBE_EXECUTED; test "$(cat /data/data)" = MOUNT_INPUT && ! echo fail > /data/new'])
  record('readonly_mount_host_unchanged',not (source/'new').exists())
  run('extra_readwrite_mount',['--mount-rw',f'{source}:/data'],['/bin/sh','-c','echo PROBE_EXECUTED; echo MOUNT_OUTPUT > /data/new'])
  record('readwrite_mount_host_written',(source/'new').read_text().strip()=='MOUNT_OUTPUT')
  run('nested_mount_destination',['--mount-ro',f'{source}:/opt/data'],['/bin/sh','-c','echo PROBE_EXECUTED; test -s /opt/data/data'])
  run('mount_source_fds_not_inherited',['--mount-ro',f'{source}:/data','--network','isolated','--allow-host','example.com'],['/workspace/probe','fds'])
  for i,destination in enumerate(['/','/usr','/usr/local','/etc','/.enclio','/workspace/x','/home','/sys','/proc/x','/data/../etc','/data//x','/data/']):
   reject('invalid_mount_destination_'+str(i),['--mount-ro',f'{source}:{destination}'])
  reject('overlapping_mount_destinations',['--mount-ro',f'{source}:/data','--mount-rw',f'{source}:/data/child'])
  reject('overlapping_mount_reverse_order',['--mount-ro',f'{source}:/data/child','--mount-rw',f'{source}:/data'])
  reject('dangerous_proc_source',['--mount-ro','/proc:/data'])
  reject('dangerous_nested_kernel_source',['--mount-ro','/sys:/data'])
  reject('mount_requires_existing_directory',['--mount-ro',f'{source}/absent:/data'])
  reject('mount_rejects_regular_file',['--mount-ro',f'{source}/data:/data'])
  reject('rw_mount_cannot_forge_result',['--mount-rw',f'{source}:/data'],source/'result.json')
  reject('rw_mount_rejects_disk_quota',['--workspace-mode','readonly','--disk-bytes','67108864','--mount-rw',f'{source}:/data'])
  reject('mount_cannot_expose_export',['--workspace-mode','tmpfs','--disk-bytes','67108864','--export',str(export),'--mount-ro',f'{export}:/data'])
  cgroup=os.getenv('ENCLIO_CGROUP_PARENT')
  if cgroup:reject('mount_cannot_expose_cgroup',['--cgroup-parent',cgroup,'--mount-ro',f'{cgroup}:/data'])
  run('ro_mount_with_disk_quota',['--workspace-mode','readonly','--disk-bytes','67108864','--mount-ro',f'{source}:/data'],['/bin/sh','-c','echo PROBE_EXECUTED; test -s /data/data'])
  for mode in ['strict','compat']:
   base=['--seccomp',mode]
   run('syscall_'+mode+'_default_deny',base,['/workspace/options_probe','selfread'],contains=('RETURN=-1 ERRNO=1',))
   run('syscall_'+mode+'_override_default_deny',base+['--syscall','process_vm_readv=allow'],['/workspace/options_probe','selfread'],contains=('DATA=SELF_READ',))
   run('syscall_'+mode+'_deny_default_allow',base+['--syscall','getppid=deny'],['/workspace/options_probe','parent'],contains=('RETURN=-1 ERRNO=1',))
   run('syscall_'+mode+'_custom_errno',base+['--syscall','getppid=errno:42'],['/workspace/options_probe','parent'],contains=('RETURN=-1 ERRNO=42',))
   run('syscall_'+mode+'_last_rule_wins',base+['--syscall','getppid=deny','--syscall','getppid=allow'],['/workspace/options_probe','parent'],contains=('ERRNO=0',))
   run('syscall_'+mode+'_kill',base+['--syscall','getppid=kill'],['/workspace/options_probe','parent'],expected=159,contains=())
  for syscall in ['memfd_create','shmget','mmap']:
   reject('memory_quota_rejects_hugetlb_override_'+syscall,['--memory-bytes','67108864','--syscall',syscall+'=allow'])
  reject('mount_count_bounded',sum((['--mount-ro',f'{source}:/data{i}'] for i in range(33)),[]))
  reject('syscall_count_bounded',['--syscall','getppid=allow']*65)
  # Reporting restrictions must not turn an exec failure into command_started.
  def setup_failure(name,rules):
   nonlocal index
   index+=1;report=root/f'startup-{index}.json'
   q=subprocess.run([binary,'run','--workspace',str(workspace),'--timeout','5','--result',str(report),*rules,'--','/does-not-exist'],capture_output=True,text=True,timeout=10)
   d=json.loads(report.read_text()) if report.exists() else {}
   record(name,q.returncode==125 and d.get('status')=='setup_error' and d.get('command_started') is False and d.get('cleanup_complete') is True,returncode=q.returncode,stdout=q.stdout,stderr=q.stderr,result=d)
  for mode in ['strict','compat']:
   prefix=['--seccomp',mode,'--syscall','execve=deny']
   setup_failure('startup_'+mode+'_write_denied',prefix+['--syscall','write=deny'])
   setup_failure('startup_'+mode+'_write_killed',prefix+['--syscall','write=kill'])
   setup_failure('startup_'+mode+'_exit_denied',prefix+['--syscall','write=deny','--syscall','exit=deny','--syscall','exit_group=deny'])
   setup_failure('startup_'+mode+'_exec_killed',['--seccomp',mode,'--syscall','execve=kill'])
   index+=1;report=root/f'quiet-{index}.json'
   q=subprocess.run([binary,'run','--workspace',str(workspace),'--result',str(report),'--seccomp',mode,'--syscall','write=deny','--','/bin/true'],capture_output=True,text=True,timeout=10)
   d=json.loads(report.read_text()) if report.exists() else {}
   record('startup_'+mode+'_write_denied_valid_exec',q.returncode==0 and d.get('command_started') is True and d.get('cleanup_complete') is True,returncode=q.returncode,stdout=q.stdout,stderr=q.stderr,result=d)
  for i,rule in enumerate(['made_up_syscall=allow','getppid=maybe','getppid=errno:0','getppid=errno:4096','getppid','*=allow']):reject('invalid_syscall_rule_'+str(i),['--syscall',rule])
 identity=json.loads(subprocess.check_output(['python3','scripts/source-id.py','--json'],text=True))
 output=dict(schema_version=1,**identity,binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),results=results,failed=sum(x['status']!='PASS' for x in results))
 Path(a.output).parent.mkdir(parents=True,exist_ok=True);Path(a.output).write_text(json.dumps(output,indent=2)+'\n');return int(output['failed']!=0)
if __name__=='__main__':raise SystemExit(main())
