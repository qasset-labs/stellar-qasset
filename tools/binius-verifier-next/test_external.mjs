// SPDX-License-Identifier: MIT
// Raw external-input Wasm execution only; this is not a Soroban host or contract ABI.
import fs from 'node:fs';
import crypto from 'node:crypto';
const [wasmPath,setupPath,proofPath,reportPath]=process.argv.slice(2);
if(!wasmPath||!setupPath||!proofPath||!reportPath) throw new Error('usage: node test_external.mjs WASM SETUP PROOF REPORT');
const bytes=fs.readFileSync(wasmPath);
const setupOriginal=fs.readFileSync(setupPath);
const proofOriginal=fs.readFileSync(proofPath);
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
if(sha(setupOriginal)!=='0d1a3b775ce006e07df6af3aa1491d2d7c29202e11985fd6045ef398cb3be424') throw new Error('wrong canonical public setup');
if(sha(proofOriginal)!=='e383a3cc44c30b0028b764e11130bdb27454221e0d67a5b82d90abe70047f461') throw new Error('wrong canonical public proof');
const scalarOriginal=Buffer.from('307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f','hex');
const actionOriginal=Buffer.from('ff2cd29f0444d641ff545753d1ccbfefdd66e1d68dedea2039e7dd64f4dab449186cc8bbb1b30a8265dfac90a55d2e641c4d3c28069aa81d6c18d8bb9d5dbe64','hex');
const module=await WebAssembly.compile(bytes);
const checks=[];
for(const [id,name,expected] of [[0,'canonical',1],[1,'changed_action',0],[2,'corrupted_proof',0],[3,'trailing_proof',0],[4,'truncated_proof',0],[5,'empty_proof',0],[6,'changed_scalar',0],[7,'padded_constraints_match_native_identity',1],[8,'unclamped_scalar',0],[9,'changed_preprocessing',0],[10,'trailing_preprocessing',0],[11,'truncated_preprocessing',0]]) {
 const instance=await WebAssembly.instantiate(module,{});
 let setup=Buffer.from(setupOriginal),proof=Buffer.from(proofOriginal),scalar=Buffer.from(scalarOriginal),action=Buffer.from(actionOriginal);
 if(id===1) action[0]^=1;
 if(id===2) proof[100]^=1;
 if(id===3) proof=Buffer.concat([proof,Buffer.from([0])]);
 if(id===4) proof=proof.subarray(0,proof.length-1);
 if(id===5) proof=Buffer.alloc(0);
 if(id===6) scalar[8]^=1;
 if(id===8) scalar[0]|=1;
 if(id===9) setup[0]^=1;
 if(id===10) setup=Buffer.concat([setup,Buffer.from([0])]);
 if(id===11) setup=setup.subarray(0,setup.length-1);
 const begin=performance.now();let result=null,runtime_error=null,repeat_result=null,prepare_ptr=null;
 try {
  prepare_ptr=instance.exports.qasset_prepare_input(setup.length,proof.length);
  if(!prepare_ptr) throw new Error('valid-sized input allocation rejected');
  const view=new Uint8Array(instance.exports.memory.buffer);
  view.set(setup,prepare_ptr);view.set(scalar,prepare_ptr+setup.length);view.set(action,prepare_ptr+setup.length+32);view.set(proof,prepare_ptr+setup.length+96);
  result=id===7?instance.exports.qasset_check_preprocessing():instance.exports.qasset_verify_external();
  repeat_result=instance.exports.qasset_verify_external();
 } catch(error) {runtime_error=String(error);}
 const rejection_code=new TextDecoder().decode(new Uint8Array(instance.exports.memory.buffer,instance.exports.qasset_error_ptr(),instance.exports.qasset_error_len()));
 const row={id,name,expected,result,runtime_error,rejection_code,repeat_result,elapsed_ms:performance.now()-begin,phase:instance.exports.qasset_phase(),allocated_end:instance.exports.qasset_allocated_end(),linear_memory_bytes:instance.exports.memory.buffer.byteLength,passed:result===expected&&runtime_error===null&&repeat_result===0};
 checks.push(row);console.log(JSON.stringify(row));
}
const bounds=[];
for(const [name,setupLen,proofLen] of [['empty_setup',0,0],['oversize_setup',3*1024*1024+1,0],['oversize_proof',1,1024*1024+1]]) {
 const instance=await WebAssembly.instantiate(module,{});const result=instance.exports.qasset_prepare_input(setupLen,proofLen);
 bounds.push({name,result,passed:result===0&&instance.exports.qasset_allocated_end()===0});
}
{
 const instance=await WebAssembly.instantiate(module,{});
 bounds.push({name:'verify_without_input',passed:instance.exports.qasset_verify_external()===0});
 const first=instance.exports.qasset_prepare_input(1,0),second=instance.exports.qasset_prepare_input(1,0);
 bounds.push({name:'input_slot_can_be_prepared_once',passed:first!==0&&second===0});
}
const vectorInstance=await WebAssembly.instantiate(module,{});
const vector=[0,1,2].map(i=>vectorInstance.exports.qasset_transcript_vector(i));
const vectorPassed=JSON.stringify(vector)===JSON.stringify([394127921,1463445479,3541783]);
const result={scope:'raw_external_input_fixed_fixture_only_not_soroban_host_or_contract',wasm_bytes:bytes.length,wasm_sha256:sha(bytes),setup_sha256:sha(setupOriginal),proof_sha256:sha(proofOriginal),transcript_vector:vector,transcript_vector_passed:vectorPassed,checks,bounds,all_passed:vectorPassed&&checks.every(r=>r.passed)&&bounds.every(r=>r.passed)};
fs.writeFileSync(reportPath,JSON.stringify(result,null,2)+'\n');
if(!result.all_passed) process.exitCode=1;
