// Public fixtures only. Raw V8 execution is not Soroban metering.
import fs from 'node:fs';
import crypto from 'node:crypto';
const [wasmPath, output] = process.argv.slice(2);
if (!wasmPath || !output) throw new Error('usage: node test_wasm.mjs WASM REPORT');
fs.writeFileSync(output, JSON.stringify({status:'in_progress',security_approved:false})+'\n');
try {
  const bytes=fs.readFileSync(wasmPath);
  const module=await WebAssembly.compile(bytes);
  const instance=await WebAssembly.instantiate(module,{});
  const checks=[];
  for(let id=0;id<=25;id++) {
    const expected=id<18?1:id===25?-1:0;
    let result=null,error=null;const start=performance.now();
    try { result=instance.exports.qasset_check_binding(id); } catch(e) {error=String(e);}
    checks.push({id,expected,result,error,elapsed_ms:performance.now()-start,passed:result===expected&&error===null});
  }
  const report={status:checks.every(c=>c.passed)?'passed_raw_wasm_key_binding_only':'failed',
    security_approved:false,scope:'Mathematical scalar-to-key relation only; no seed proof or recovery authorization; not Soroban host metering',
    wasm_bytes:bytes.length,wasm_sha256:crypto.createHash('sha256').update(bytes).digest('hex'),
    imports:WebAssembly.Module.imports(module),exports:WebAssembly.Module.exports(module),
    linear_memory_bytes:instance.exports.memory.buffer.byteLength,checks};
  fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n');
  if(report.status==='failed') process.exitCode=1;
  console.log(JSON.stringify({status:report.status,checks:checks.length,wasm_bytes:bytes.length,linear_memory_bytes:report.linear_memory_bytes}));
} catch(error) {
  fs.writeFileSync(output,JSON.stringify({status:'failed',security_approved:false,error:String(error)})+'\n');
  throw error;
}
