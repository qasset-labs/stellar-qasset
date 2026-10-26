import os,resource,pathlib,json,subprocess,time,hashlib,math
base=pathlib.Path('/tmp/qasset-binius-rate-results');base.mkdir(exist_ok=True)
binary='/tmp/qasset-binius-target/release/qasset-binius-rate-research'
action='00'*64;scalar='307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f'
def limits():
 resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3));resource.setrlimit(resource.RLIMIT_CPU,(600,600))
env=os.environ.copy();env['RAYON_NUM_THREADS']='2'
records=[]
for rate in [2,3,4,5]:
 out=base/str(rate);out.mkdir(exist_ok=True)
 cmd=['/usr/bin/time','-f','{"peak_rss_kib":%M}','-o',str(out/'resource.json'),'--',binary,'prove',str(rate),action,str(out/'proof.bin'),str(out/'native.json')]
 start=time.monotonic()
 with (out/'stdout.txt').open('wb') as stdout,(out/'stderr.txt').open('wb') as stderr:
  try:
   p=subprocess.run(cmd,stdout=stdout,stderr=stderr,env=env,preexec_fn=limits,timeout=600);code=p.returncode
  except subprocess.TimeoutExpired:code='timeout'
 record={'log_inv_rate':rate,'query_count':math.ceil(96/-math.log2((1+2**-rate)/2)),'returncode':code,'elapsed_seconds':time.monotonic()-start,'address_space_limit_bytes':4*1024**3,'rayon_threads':2,'action_scope':'zero dummy digest for parameter-size comparison only; not a canonical recovery request','max_rss_kib_cumulative':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
 if (out/'resource.json').exists():
  try:record['measured_resources']=json.loads((out/'resource.json').read_text())
  except json.JSONDecodeError:record['resource_text']=(out/'resource.json').read_text()
 if (out/'native.json').exists():record['native']=json.loads((out/'native.json').read_text())
 if code==0:
  proof=(out/'proof.bin').read_bytes();record['proof_sha256']=hashlib.sha256(proof).hexdigest()
  checks={}
  for name,changedrate,changedaction in [('valid',rate,action),('changed_action',rate,'01'+action[2:]),('changed_rate',1 if rate!=1 else 2,action)]:
   args=[binary,'verify',str(changedrate),str(out/'proof.bin'),scalar,changedaction]
   p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,preexec_fn=limits,timeout=600)
   checks[name]={'returncode':p.returncode,'stdout':p.stdout.decode(),'stderr':p.stderr.decode()}
  record['separate_verifier_checks']=checks
 (out/'execution.json').write_text(json.dumps(record,indent=2)+'\n');records.append(record)
 (base/'matrix.json').write_text(json.dumps(records,indent=2)+'\n')
 print(json.dumps(record),flush=True)
