// SPDX-License-Identifier: MIT
// Compare unchanged native/table arithmetic with the optional repeated-squaring strategy.
import fs from 'node:fs';
import crypto from 'node:crypto';
const [baselinePath,compactPath,referencePath,reportPath]=process.argv.slice(2);
const reference=fs.readFileSync(referencePath,'utf8').trim().split('\n').map(line=>line.trim().split(' '));
const results=[];
for(const [name,path] of [['original_wasm_table',baselinePath],['compact_wasm_squaring',compactPath]]) {
 const raw=fs.readFileSync(path);const {instance}=await WebAssembly.instantiate(raw,{});const failures=[];const output=[];const begin=performance.now();
 for(let i=0;i<reference.length;i++) {
  const [input,expected,product]=reference[i];const x=BigInt('0x'+input);
  const words=[0,1,2,3].map(n=>Number((x>>BigInt(n*32))&0xffffffffn));
  const identity=instance.exports.qasset_arithmetic_inverse(...words);
  const inverseWords=[0,1,2,3].map(n=>BigInt(instance.exports.qasset_arithmetic_word(n)>>>0));
  const actual=inverseWords.reduce((n,w,i)=>n|(w<<BigInt(i*32)),0n).toString(16).padStart(32,'0');
  const expectedProduct=x===0n?'00000000000000000000000000000000':'00000000000000000000000000000001';
  if(actual!==expected||identity!==1||product!==expectedProduct)failures.push({index:i,input,expected,actual,identity,native_product:product});
  output.push(actual);
 }
 results.push({name,wasm_sha256:crypto.createHash('sha256').update(raw).digest('hex'),vectors:reference.length,elapsed_ms:performance.now()-begin,output_sha256:crypto.createHash('sha256').update(output.join('\n')+'\n').digest('hex'),failures,all_passed:failures.length===0});
}
const report={scope:'deterministic_field_arithmetic_equivalence_only_not_security_proof',reference:'unchanged_original_native64_Binius_field_inverse',reference_sha256:crypto.createHash('sha256').update(fs.readFileSync(referencePath)).digest('hex'),vectors:reference.length,input_coverage:['zero','one','two','three','all_bits_one','highest_bit','all128_single_bit_basis_values','512_SHA256_derived_deterministic_pseudorandom_values'],results,all_passed:results.every(r=>r.all_passed)&&results[0].output_sha256===results[1].output_sha256};
fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));if(!report.all_passed)process.exitCode=1;
