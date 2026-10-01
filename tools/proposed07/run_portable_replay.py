#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the local replay EXAMPLE as a real subprocess; no builds or network.

Requires an already-built binary and a fresh output directory. Preserves each
command, stdout, stderr, exit and actual report. Explicit report expectations
are not an independent implementation or authenticated policy. Never repairs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def projection(report, field):
    rows=report['records']
    selection={'statement_statuses':('statement_check','status'), 'membership':('membership','status'),
               'disclosure_policy':('disclosure_policy','status'), 'contradictions':('summary','value_contradictions'),
               'forbidden':('summary','attribution_forbidden'),'evidence_failures':('summary','evidence_failures')}
    if field in selection:
        a,b=selection[field];return [row[a][b] for row in rows]
    if field=='chain_status':return report['chain']['check']['status']
    if field=='affiliation_changes':return len(report['chain']['affiliation_changes'])
    if field=='presentation_states':return [row['presentation_state'] for row in rows]
    if field=='requested_availability':return [[f['availability'] for f in row['requested_facts']] for row in rows]
    raise ValueError('unknown expected projection: '+field)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    binary,fixtures,output=(x.resolve() for x in (a.binary,a.fixtures,a.output))
    if not binary.is_file() or not fixtures.is_dir():p.error('existing binary and fixtures required')
    if output.exists() or output.is_relative_to(fixtures) or fixtures.is_relative_to(output):p.error('fresh nonoverlapping output directory required')
    original={x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in fixtures.iterdir() if x.is_file()}
    output.mkdir(parents=True);catalog=json.loads((fixtures/'catalog.json').read_text());runs=[];measurements=[]
    key=fixtures/'public-key.hex'
    def run(label,args,expected_exit):
        command=[str(binary)]+[str(x) for x in args];start=time.perf_counter_ns()
        try:
            done=subprocess.run(command,capture_output=True,timeout=120,check=False)
            code=done.returncode;stdout,stderr=done.stdout,done.stderr
        except subprocess.TimeoutExpired as exc:
            code=None;stdout,stderr=exc.stdout or b'',exc.stderr or b''
        row={'label':label,'command':command,'exit':code,'expected_exit':expected_exit,'elapsed_ns':time.perf_counter_ns()-start}
        (output/(label+'.stdout')).write_bytes(stdout);(output/(label+'.stderr')).write_bytes(stderr)
        runs.append(row);(output/'COMMANDS.json').write_text(json.dumps(runs,indent=2)+'\n')
        if code!=expected_exit:raise AssertionError(row)
        return stdout,stderr
    try:
        for case in catalog['cases']:
            name=case['file']
            if Path(name).name!=name:raise ValueError('unsafe fixture file path')
            source=fixtures/name
            if hashlib.sha256(source.read_bytes()).hexdigest()!=case['sha256']:raise ValueError('fixture changed')
            report_path=output/(case['id']+'.report.json')
            stdout,_=run(case['id'],['--mode',case['mode'],'--input',source,'--key',key,'--output',report_path],0)
            assert stdout==b''
            raw=report_path.read_bytes();report=json.loads(raw)
            for field,value in case['expected'].items():assert projection(report,field)==value,(case['id'],field)
            assert report['latest_or_complete_history']['status']=='unestablished'
            assert report['application_acceptance']['status']=='unestablished'
            assert report['registration']['status']=='not-evaluated'
            assert 'accepted' not in report and 'valid' not in report
            assert report['input_document_digest']=='sha256:'+case['sha256']
            measurements.append({'id':case['id'],'mode':case['mode'],**report['measurements'],
                                 'actual_report_bytes':len(raw),'report_sha256':hashlib.sha256(raw).hexdigest(),
                                 'elapsed_ns':runs[-1]['elapsed_ns'],'timing_scope':'one local process invocation, not production benchmark'})
        run('help',['--help'],0)
        run('missing-arguments',[],2)
        run('missing-key',['--mode','single','--input',fixtures/'single-match.json'],2)
        run('mode-cardinality',['--mode','single','--input',fixtures/'chain-three.json','--key',key],2)
        existing=output/'single-match.report.json';before=existing.read_bytes()
        run('no-overwrite',['--mode','single','--input',fixtures/'single-match.json','--key',key,'--output',existing],2)
        assert existing.read_bytes()==before
        run('no-input-overwrite',['--mode','single','--input',fixtures/'single-match.json','--key',key,'--output',fixtures/'single-match.json'],2)
        malformed=output/'malformed.json';malformed.write_text('{')
        absent=output/'not-created.json'
        run('invalid-framing',['--mode','single','--input',malformed,'--key',key,'--output',absent],2);assert not absent.exists()
        badkey=output/'non-ascii-key.hex';badkey.write_text('\u00a0'+key.read_text())
        run('invalid-key-spelling',['--mode','single','--input',fixtures/'single-match.json','--key',badkey],2)
        new=output/'deterministic-repeat.json'
        run('deterministic-repeat',['--mode','single','--input',fixtures/'single-match.json','--key',key,'--output',new],0)
        assert new.read_bytes()==before
        rawout,_=run('stdout-output',['--mode','single','--input',fixtures/'single-match.json','--key',key],0)
        assert rawout==before
        (output/'MEASUREMENTS.json').write_text(json.dumps(measurements,indent=2)+'\n')
        result={'native_example_executed':True,'fixture_cases':len(catalog['cases']),'total_subprocess_invocations':len(runs),
                'all_expected_outcomes':True,'report_exit_zero_means_processed_not_accepted':True}
        (output/'RESULTS.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    finally:
        current={x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in fixtures.iterdir() if x.is_file()}
        preserved=original==current
        (output/'SOURCE_PRESERVATION.json').write_text(json.dumps({'fixture_files':len(original),'unchanged':preserved},indent=2)+'\n')
        if not preserved:raise AssertionError('fixture directory changed')

if __name__=='__main__':main()
