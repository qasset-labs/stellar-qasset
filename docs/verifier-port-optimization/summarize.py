"""Summarize a standalone optimizer experiment; never edits the frozen source package."""
from pathlib import Path
import hashlib,json
ROOT=Path('/tmp/qasset-binius-optimize-probe')
PACKAGE=Path('/tmp/qasset-binius-port-package')
ORIGINAL=PACKAGE/'target/bin/qasset_binius_wasm_fixture.wasm'
OPTIMIZED=ROOT/'qasset_binius_wasm_fixture.optimized.wasm'
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def sections(path):
 raw=path.read_bytes();at=8;out=[]
 def leb(offset):
  n=0;shift=0
  while True:
   b=raw[offset];offset+=1;n|=(b&127)<<shift
   if b<128:return n,offset
   shift+=7
 while at<len(raw):
  kind=raw[at];at+=1;n,at=leb(at);out.append({'id':kind,'payload_bytes':n});at+=n
 return out
provenance=json.loads((PACKAGE/'provenance.json').read_text())
assert all(digest(PACKAGE/path)==expected for path,expected in provenance['source_sha256'].items())
wasm=json.loads((ROOT/'wasm-results.json').read_text());inspection=json.loads((ROOT/'inspection.json').read_text())
assert wasm['all_passed'] and len(wasm['checks'])==9 and wasm['transcript_vector_passed']
assert all(row['error'] is None and row['passed'] for row in wasm['checks'])
assert inspection['imports']==[] and inspection['float_operator_count']==0
assert inspection['no_float_simd_threads_validation']=='passed'
assert inspection['memories']==[{'initial_pages':67,'maximum_pages':640,'memory64':False,'shared':False}]
before=sections(ORIGINAL);after=sections(OPTIMIZED)
code_before=next(s['payload_bytes'] for s in before if s['id']==10)
code_after=next(s['payload_bytes'] for s in after if s['id']==10)
report={
 'schema':'qasset-binius-binaryen-size-probe-v1',
 'status':'passed_raw_wasm_fixed_fixture_optimizer_probe_only',
 'security_approved':False,'soroban_compatible':False,
 'frozen_package_source_manifest_verified':True,'frozen_source_count':len(provenance['source_sha256']),
 'frozen_provenance_sha256':digest(PACKAGE/'provenance.json'),
 'optimizer':'stellar CLI26.0.0 embedded optimizer; optimize command deprecated in favor of build --optimize',
 'commands':[
  ['stellar','contract','optimize','--wasm',str(ORIGINAL),'--wasm-out',str(OPTIMIZED)],
  [str(PACKAGE/'target/bin/qasset-wasm-inspect'),str(OPTIMIZED)],
  ['node',str(PACKAGE/'test_wasm.mjs'),str(OPTIMIZED),str(ROOT/'wasm-results.json')]],
 'source':{'path':str(ORIGINAL),'sha256':digest(ORIGINAL),'bytes':ORIGINAL.stat().st_size,'code_section_bytes':code_before,'sections':before},
 'optimized':{'path':str(OPTIMIZED),'sha256':digest(OPTIMIZED),'bytes':OPTIMIZED.stat().st_size,'code_section_bytes':code_after,'sections':after},
 'code_section_reduction_bytes':code_before-code_after,
 'code_section_reduction_percent':100*(code_before-code_after)/code_before,
 'recorded_contract_code_cap_bytes':131072,
 'code_section_exceeds_recorded_cap_by_bytes':code_after-131072,
 'raw_wasm_checks_passed':9,'transcript_golden_passed':True,
 'largest_observed_linear_memory_bytes':max(row['linear_memory_bytes'] for row in wasm['checks']),
 'actual_memory_maximum_bytes':640*65536,
 'inspection':inspection,'raw_wasm_results_sha256':digest(ROOT/'wasm-results.json'),
 'applicable_instructions_read_before_port':[
  '/tmp/qasset-binius64-pinned/AGENTS.md','/tmp/qasset-binius64-pinned/CONTRIBUTING.md'],
 'limitations':['Raw Node/V8 execution is not Soroban host metering','Optimized module embeds public setup/proof fixture data','Code section alone remains above recorded contract code cap','These checks do not establish independent quantum knowledge or zero-knowledge security','No Stellar RPC, transaction or deployment was performed'],
 'stellar_rpc_requests':0,'submitted_transactions':0,
}
(ROOT/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['status','code_section_reduction_bytes','code_section_reduction_percent','code_section_exceeds_recorded_cap_by_bytes','largest_observed_linear_memory_bytes']},indent=2))
