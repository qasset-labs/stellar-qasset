#!/usr/bin/env python3
"""Measure a public-fixture Soroban ABI. Never authorizes recovery or calls RPC."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def source_snapshot():
    files=[Path(__file__)]
    for name in ['binius-soroban-research','binius-verifier-next']:
        files += [p for p in (ROOT/'tools'/name).rglob('*') if p.is_file()
                  and not set(p.relative_to(ROOT).parts)&{'target','__pycache__','.git'}]
    return {str(p.relative_to(ROOT)):sha(p) for p in sorted(files)}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-dir',type=Path,default=ROOT/'target/soroban-verifier-build')
    parser.add_argument('--host-target-dir',type=Path,default=ROOT/'target/soroban-host-build')
    parser.add_argument('--setup',type=Path,default=ROOT/'tools/binius-verifier-next/target/fixtures/fixed-setup.bin')
    parser.add_argument('--proof',type=Path,default=ROOT/'target/binius-seed-research/proof.bin')
    parser.add_argument('--output-dir',type=Path,default=ROOT/'target/binius-soroban-research')
    parser.add_argument('--report',type=Path,default=ROOT/'docs/binius-soroban-research.json')
    parser.add_argument('--allow-oversize-registration',action='store_true',help='Local diagnostic only: bypass registration limits, retain explicit call CPU/memory budgets.')
    parser.add_argument('--expanded-diagnostic',action='store_true',help='Measure with 12B CPU/256MiB; never a network-feasibility pass.')
    args=parser.parse_args();args.output_dir.mkdir(parents=True,exist_ok=True)
    record={'schema':'qasset-binius-soroban-research-v1','status':'in_progress',
            'recorded_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'security_approved':False,
            'stellar_rpc_requests':0,'submitted_transactions':0,'commands':[],
            'scope':'Actual Wasm local SDK cost measurement only. Large argument transport bypasses transaction caps; no account authority or production approval.'}
    def save():
        tmp=args.report.with_suffix('.tmp');tmp.write_text(json.dumps(record,indent=2)+'\n');tmp.replace(args.report)
    save()
    try:
        before=source_snapshot();record['source_sha256']=before;save()
        env=os.environ.copy()
        removed=['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET']
        removed += [k for k in env if k.startswith('CARGO_PROFILE_RELEASE_')]
        record['removed_build_overrides']={k:bool(env.pop(k,'')) for k in removed}
        def run(command,label,timeout=600):
            result=subprocess.run(command,cwd=ROOT,env=env,text=True,capture_output=True,timeout=timeout)
            (args.output_dir/(label+'.stdout')).write_text(result.stdout)
            (args.output_dir/(label+'.stderr')).write_text(result.stderr)
            record['commands'].append({'argv':command,'exit_code':result.returncode,
                'stdout_sha256':hashlib.sha256(result.stdout.encode()).hexdigest(),
                'stderr_sha256':hashlib.sha256(result.stderr.encode()).hexdigest()});save()
            if source_snapshot()!=before:raise RuntimeError('source changed during experiment')
            if result.returncode:raise RuntimeError('tool failed: '+label)
            return result.stdout
        record['versions']={name:run(cmd,'version-'+name).strip() for name,cmd in [
            ('rustc',['rustc','+1.94.1','-Vv']),('cargo',['cargo','+1.94.1','-V']),('stellar',['stellar','--version'])]}
        wasm_manifest='tools/binius-soroban-research/compact/Cargo.toml'
        host_manifest='tools/binius-soroban-research/host-runner/Cargo.toml'
        run(['cargo','+1.94.1','rustc','--manifest-path',wasm_manifest,'--locked','--offline','--release','--lib',
             '--target','wasm32v1-none','--target-dir',str(args.target_dir.resolve()),'--','-C','link-arg=--max-memory=41943040'],'wasm-build')
        run(['cargo','+1.94.1','build','--manifest-path',host_manifest,'--locked','--offline','--target-dir',str(args.host_target_dir.resolve())],'host-build')
        raw=args.target_dir/'wasm32v1-none/release/qasset_binius_soroban_compact_research.wasm'
        optimized=args.output_dir/'qasset_binius_soroban_compact.optimized.wasm'
        run(['stellar','contract','optimize','--wasm',str(raw.resolve()),'--wasm-out',str(optimized.resolve())],'optimize')
        result_path=args.output_dir/'host.json'
        host=args.host_target_dir/'debug/qasset-soroban-verifier-host-diagnostic'
        command=[str(host.resolve()),str(optimized.resolve()),str(args.setup.resolve()),str(args.proof.resolve()),
                 str(result_path.resolve()),'diagnostic' if args.expanded_diagnostic else 'recorded']
        if args.allow_oversize_registration:command.append('allow-oversize-registration')
        run(command,'host-execution',timeout=240)
        measurement=json.loads(result_path.read_text())
        valid_statuses={'failed_harness_or_registration','measured_execution_failure_not_proof_rejection',
                        'measured_actual_wasm_verification_only','measured_false_result_not_recovery_approval'}
        if measurement.get('status') not in valid_statuses or measurement.get('security_approved') is not False:
            raise RuntimeError('incomplete or overstated host execution report')
        if measurement.get('wasm_sha256')!=sha(optimized) or measurement.get('setup_sha256')!=sha(args.setup) or measurement.get('proof_sha256')!=sha(args.proof):
            raise RuntimeError('host artifact/input mismatch')
        if measurement.get('registration_succeeded'):
            if measurement.get('registration_limits_overridden') is not args.allow_oversize_registration:
                raise RuntimeError('unreported registration override')
            cpu,mem=(12000000000,268435456) if args.expanded_diagnostic else (400000000,41943040)
            if measurement.get('cpu_limit')!=cpu or measurement.get('memory_limit')!=mem:
                raise RuntimeError('unexpected budget configuration')
        record.update(status='completed_actual_sdk_measurement_only_not_recovery',measurement=measurement,
            wasm={'bytes':optimized.stat().st_size,'sha256':sha(optimized)},
            host_binary_sha256=sha(host),artifact_directory=str(args.output_dir.resolve()),
            full_verification_completed=measurement.get('accepted') is True,
            feasible_recovery_demonstrated=False,
            limits=['Registration may be explicitly overridden for local diagnostics; oversized code remains inadmissible.',
                    'Budget exhaustion is execution failure, never proof rejection.',
                    'Expanded budgets and already-created large host arguments are not network feasibility.',
                    'Immutable preprocessing, generic trusted-key policy, atomic account lifecycle and independent quantum security review remain required.'])
        save();print(json.dumps({'status':record['status'],'measurement_status':measurement['status'],'wasm_bytes':optimized.stat().st_size,'full_verification_completed':record['full_verification_completed']}))
    except BaseException as error:
        record.update(status='failed',error_type=type(error).__name__,error=str(error));save();raise

if __name__=='__main__':main()
