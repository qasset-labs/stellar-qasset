#!/usr/bin/env python3
"""Read public Testnet settings only; never signs or submits a transaction."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    record={'schema':'qasset-verifier-network-limits-v1','status':'in_progress',
            'recorded_at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
            'network':'testnet','read_only':True,'submitted_transactions':0,
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    def save():
        temporary=args.output.with_suffix('.tmp')
        temporary.write_text(json.dumps(record,indent=2)+'\n');temporary.replace(args.output)
    save()
    try:
        record['cli_version']=subprocess.run(['stellar','--version'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
        with tempfile.TemporaryDirectory(prefix='qasset-readonly-limits-') as config:
            command=['stellar','--config-dir',config,'--no-cache','network','settings',
                     '--rpc-url','https://soroban-testnet.stellar.org',
                     '--network-passphrase','Test SDF Network ; September 2015','--output','json']
            record['command']=command
            result=subprocess.run(command,capture_output=True,text=True,timeout=40,check=True)
        record['stderr']=result.stderr
        record['raw_response_sha256']=hashlib.sha256(result.stdout.encode()).hexdigest()
        response=json.loads(result.stdout);record['response']=response
        entries=response['updated_entry']
        def one(key):
            values=[entry[key] for entry in entries if key in entry]
            if len(values)!=1:raise ValueError('missing/ambiguous setting '+key)
            return values[0]
        compute=one('contract_compute_v0');bandwidth=one('contract_bandwidth_v0')
        sizes=[entry['contract_max_size_bytes'] for entry in entries if 'contract_max_size_bytes' in entry]
        if len(sizes)!=1:raise ValueError('missing code limit')
        record['decoded_limits']={'contract_max_size_bytes':sizes[0],
            'tx_max_size_bytes':bandwidth['tx_max_size_bytes'],
            'tx_max_instructions':compute['tx_max_instructions'],
            'tx_memory_limit':compute['tx_memory_limit']}
        warning=re.search(r'Network protocol version is (\d+) but the stellar-cli supports (\d+)',result.stderr)
        record['protocol_compatibility_warning']=warning.group(0) if warning else None
        record['status']='passed_read_only_partial_snapshot' if warning else 'passed_read_only_snapshot'
        record['scope']='Public RPC settings only. A CLI protocol mismatch may omit settings; this snapshot is not full compatibility, cost simulation, network admission or production feasibility approval.'
        save();print(json.dumps(record['decoded_limits'],indent=2))
    except Exception as error:
        record.update(status='failed',error_type=type(error).__name__,error=str(error));save();raise

if __name__=='__main__':main()
