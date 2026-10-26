// Copyright 2026 The Binius Developers
// Each case has fresh linear memory; this is raw V8 execution, not Soroban metering.
import fs from 'node:fs';
import crypto from 'node:crypto';
const path=process.argv[2];
const output=process.argv[3];
if(!path||!output) throw new Error('usage: node test_wasm.mjs WASM REPORT');
const bytes=fs.readFileSync(path); const start=performance.now();
const module=await WebAssembly.compile(bytes);const compile_ms=performance.now()-start;
const results=[];
for(const [id,name,expected] of [[0,'canonical',1],[1,'changed_action',0],[2,'corrupted_proof',0],[3,'trailing_proof',0],[4,'truncated_proof',0],[5,'empty_proof',0],[6,'changed_scalar',0],[7,'padded_constraints_match_native_identity',1],[8,'unclamped_scalar',0]]) {
 const instance=await WebAssembly.instantiate(module,{}); const begin=performance.now();
 let result=null,error=null;
 try{result=instance.exports.qasset_verify_fixture(id);}catch(e){error=e.toString();}
 const detail=new TextDecoder().decode(new Uint8Array(instance.exports.memory.buffer,instance.exports.qasset_error_ptr?.()??0,instance.exports.qasset_error_len?.()??0));
 const row={id,name,expected,result,error,detail,elapsed_ms:performance.now()-begin,phase:instance.exports.qasset_phase(),allocated_end:instance.exports.qasset_allocated_end(),linear_memory_bytes:instance.exports.memory.buffer.byteLength,passed:result===expected&&error===null};
 results.push(row);console.log(JSON.stringify(row));
}
const vectorInstance=await WebAssembly.instantiate(module,{});
const vector=[0,1,2].map(i=>vectorInstance.exports.qasset_transcript_vector(i));
const vector_passed=JSON.stringify(vector)===JSON.stringify([394127921,1463445479,3541783]);
const report={transcript_vector:vector,transcript_vector_passed:vector_passed,scope:'raw_wasm_fixture_execution_only_not_soroban_metering_or_contract',wasm_bytes:bytes.length,wasm_sha256:crypto.createHash('sha256').update(bytes).digest('hex'),compile_ms,checks:results,all_passed:vector_passed&&results.every(r=>r.passed)};
fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
if(!report.all_passed) process.exitCode=1;
