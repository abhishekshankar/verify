#!/usr/bin/env python3
"""CloudShell glue for exact-version evidence transfer and fixed SSM operations.

prepare refreshes READY evidence and repoints the unused SOURCE bridge. rehearse
runs the read-only source rehearsal. execute refreshes the completed standalone
drain proof, pins it, then invokes the reviewed final coordinator. poll resumes
an existing SSM command; never blindly resubmit an uncertain execute operation.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import time
import uuid
import base64

ACCOUNT = "842676017161"
INSTANCE = "i-0e3509a6723d2c0c5"
REGION = "us-west-2"
BUCKET = "verify-ledger-migration-842676017161-20261114"
ROUTE_SHA256 = "38f53f927aba8b19484f44f0563cbb4bd119114af04f87522c5849fe546e2dea"
ROOT = Path.home() / "aws-project-migrations-20261114"
REHEARSAL = ROOT / "verify-last-rehearsal-result.json"

# Native target Python supplies boto3; all application/database commands use the
# already installed venv. Input is data in one base64 argument, never shell code.
TARGET_WORKER = r'''
import base64,hashlib,json,os,re,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
import boto3
from botocore.config import Config
payload=json.loads(base64.b64decode(sys.argv[1],validate=True));os.umask(0o077)
work=Path('/opt/verify-migration/cutover');current=Path('/opt/verify/current')
def check(ok,reason):
    if not ok:raise RuntimeError(reason)
def private(path,data):
    if path.exists():
        check(path.stat().st_uid==0 and not path.stat().st_mode&0o077 and path.read_bytes()==data,'Existing private evidence differs')
    else:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def run(module,arguments,timeout):
    environment={k:v for k,v in os.environ.items() if not k.startswith(('PG','VERIFY_'))}
    environment.update(PYTHONPATH=str(current/'src')+':'+str(current),
        PGSERVICEFILE=str(work/'source-service.conf'),PGPASSFILE=str(work/'source.pgpass'))
    result=subprocess.run([str(current/'.venv/bin/python'),'-m',module]+arguments,env=environment,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if result.returncode:
        error=work/('glue-error-'+payload['intentId']+'-'+str(time.time_ns())+'.json')
        private(error,json.dumps({'returncode':result.returncode,'stdout':result.stdout.decode(errors='replace'),
            'stderr':result.stderr.decode(errors='replace')}).encode())
        raise RuntimeError('Reviewed target command failed; private evidence '+str(error))
    return json.loads(result.stdout)
try:
    check(os.geteuid()==0 and payload['mode'] in ('prepare','rehearse','execute'),'Unexpected target identity or operation')
    identity=json.loads(Path('/etc/verify/target-install.json').read_text())
    check(identity.get('accountId')=='842676017161' and identity.get('instanceId')=='i-0e3509a6723d2c0c5','Target identity mismatch')
    check(work.stat().st_uid==0 and not work.stat().st_mode&0o077,'Migration directory is not private')
    hashes={'cutover.py':'240021ca6954155ae3c181f3040322ed838020a3860bf1e7582f4204e05d8a8a',
        'attest_source_route.py':'e23a00cb3ae4f0cbc65f53634fc63065267328993ba9223c2432658b142dd291',
        'prepare_standalone_source.py':'03020d4d8b8d830070a0e77fc8c8c819836b16b03b2fc83a8359eb18c7f3f2ed',
        'recover_source_bridge.py':'2d1d1d344dc1acdf538f18409214dbf2de382d40dded7ec963560610a30e8309'}
    for filename,digest in hashes.items():
        check(hashlib.sha256((current/'hosted/lightsail'/filename).read_bytes()).hexdigest()==digest,'Deployed reviewed helper checksum changed')
    mode=payload['mode']
    if mode!='rehearse':
        evidence=payload['evidence'];location=evidence['s3'];digest=evidence['sha256']
        check(location['bucket']=='verify-ledger-migration-842676017161-20261114'
            and location['key'].startswith('live/verify-ledger/routing/standalone-source-20261114/')
            and location.get('versionId') not in (None,'','null') and re.fullmatch('[a-f0-9]{64}',digest),'Unreviewed evidence object')
        s3=boto3.client('s3',region_name='us-west-2',config=Config(connect_timeout=2,read_timeout=4,retries={'max_attempts':0}))
        response=s3.get_object(Bucket=location['bucket'],Key=location['key'],VersionId=location['versionId'],ExpectedBucketOwner='842676017161')
        try:
            check(0<response['ContentLength']<=1024*1024 and response.get('VersionId')==location['versionId']
                and response.get('ServerSideEncryption')=='AES256','Evidence object version/encryption/size differs')
            raw=response['Body'].read(1024*1024+1)
        finally:response['Body'].close()
        check(len(raw)==response['ContentLength'] and hashlib.sha256(raw).hexdigest()==digest,'Downloaded evidence checksum differs')
        report=json.loads(raw);age=(datetime.now(timezone.utc)-datetime.fromisoformat(report['capturedAtUtc'])).total_seconds()
        expected='STANDALONE_SOURCE_TASK_READY' if mode=='prepare' else 'SOURCE_HTTP_DRAIN_AND_WRITER_NETWORK_VERIFIED'
        check(report.get('status')==expected and 0<=age<=(120 if mode=='prepare' else 300),'Evidence expired or has wrong state')
        evidence_path=work/('glue-'+mode+'-'+digest[:16]+'.json');private(evidence_path,raw)
    if mode=='prepare':
        result=run('hosted.lightsail.prepare_standalone_source',['prepare','--ready-report',str(evidence_path),'--sha256',digest],60)
        check(result.get('status')=='STANDALONE_SOURCE_TRANSITION_VERIFIED','Standalone bridge preparation was not proved')
    elif mode=='rehearse':
        result=run('hosted.lightsail.cutover',['rehearse','--config',str(work/'coordinator.json')],90)
        check(result.get('status')=='REHEARSAL_PASSED','Actual-source rehearsal did not pass')
    else:
        saved=payload['rehearsal'];rehearsal=Path(saved['report'])
        check(rehearsal.parent==work and re.fullmatch('[a-f0-9]{12}-rehearsal.json',rehearsal.name),'Unexpected rehearsal report path')
        check(rehearsal.stat().st_uid==0 and not rehearsal.stat().st_mode&0o077,'Rehearsal evidence is not private')
        raw=rehearsal.read_bytes();check(hashlib.sha256(raw).hexdigest()==saved['reportSha256'],'Rehearsal checksum changed')
        previous=json.loads(raw);age=(datetime.now(timezone.utc)-datetime.fromisoformat(previous['capturedAtUtc'])).total_seconds()
        check(previous.get('status')=='REHEARSAL_PASSED' and 0<=age<=1800 and previous.get('measuredSeconds',999)<=8,'Fresh fast rehearsal required')
        accepted=run('hosted.lightsail.attest_source_route',['accept','--routing-report',str(evidence_path),'--sha256',digest],30)
        check(accepted.get('status')=='SOURCE_ROUTING_EVIDENCE_PINNED','Final routing proof was not pinned')
        result=run('hosted.lightsail.attest_source_route',['execute','--rehearsal',str(rehearsal)],90)
        check(result.get('status')=='TARGET_AUTHORITATIVE','Target authority is not confirmed; inspect durable state before any recovery')
    if result.get('report'):
        path=Path(result['report']);raw=path.read_bytes();details=json.loads(raw)
        result.update(reportSha256=hashlib.sha256(raw).hexdigest(),reportCapturedAtUtc=details.get('capturedAtUtc'))
    result.update(glueMode=mode,intentId=payload['intentId'])
    private(work/('glue-result-'+payload['intentId']+'.json'),(json.dumps(result,indent=2)+'\n').encode())
    print(json.dumps(result))
except Exception as error:
    print(json.dumps({'status':'SSM_GLUE_BLOCKED','errorClass':type(error).__name__,
        'reason':str(error) if type(error) is RuntimeError else 'Inspect private target state; credential details suppressed',
        'intentId':payload.get('intentId'),'mode':payload.get('mode'),
        'recovery':'Never resubmit uncertain execute or restore SOURCE without inspecting durable authority'}))
    raise SystemExit(2)
'''


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def private_save(path, value):
    raw = (json.dumps(value, indent=2) + "\n").encode()
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def command_for(payload):
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return "/usr/bin/python3 - " + shlex.quote(encoded) + " <<'VERIFY_REVIEWED_SSM_WORKER'\n" + TARGET_WORKER + "\nVERIFY_REVIEWED_SSM_WORKER"


def read_rehearsal_record():
    require(REHEARSAL.stat().st_uid == os.getuid() and not REHEARSAL.stat().st_mode & 0o077,
            "Recorded rehearsal result is not private")
    result = json.loads(REHEARSAL.read_text())
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(result["reportCapturedAtUtc"])).total_seconds()
    require(result.get("status") == "REHEARSAL_PASSED" and 0 <= age <= 1800 and result.get("measuredSeconds", 999) <= 8,
            "Run and poll a successful fresh rehearsal first")
    return result


def pending_execution():
    path = ROOT / "verify-execute-intent.json"
    require(path.is_file() and path.stat().st_uid == os.getuid() and not path.stat().st_mode & 0o077,
            "The durable execute intent is missing or is not private")
    record = json.loads(path.read_text())
    require(record.get("payload", {}).get("mode") == "execute"
            and re.fullmatch("[a-f0-9]{32}", record["payload"].get("intentId", ""))
            and re.fullmatch("[a-f0-9]{64}", record.get("commandSha256", "")), "Execute intent is malformed")
    return record


def reserve_execution(payload, command):
    path = ROOT / "verify-execute-intent.json"
    require(not path.exists(), "An execute intent already exists; use resume-execute or poll, never submit another execute")
    record = {"payload": payload, "commandSha256": hashlib.sha256(command.encode()).hexdigest(),
              "comment": "Verify guarded execute " + payload["intentId"],
              "createdAtUtc": datetime.now(timezone.utc).isoformat(), "submissionState": "MAY_HAVE_BEEN_SUBMITTED"}
    private_save(path, record)
    return record


def discover_execution(ssm, record):
    """Find only the saved submission; empty/ambiguous history never permits retry."""
    token, matches, deadline = None, [], time.monotonic() + 20
    while True:
        require(time.monotonic() < deadline, "SSM discovery budget expired; retain the intent and resume later")
        arguments = {"InstanceId": INSTANCE, "MaxResults": 50}
        if token:
            arguments["NextToken"] = token
        response = ssm.list_commands(**arguments)
        for item in response.get("Commands", []):
            if item.get("Comment") != record["comment"]:
                continue
            commands = item.get("Parameters", {}).get("commands", [])
            require(item.get("InstanceIds") == [INSTANCE] and item.get("DocumentName") == "AWS-RunShellScript"
                    and len(commands) == 1 and hashlib.sha256(commands[0].encode()).hexdigest() == record["commandSha256"],
                    "An intent-matched SSM command has a different target or payload; preserve the blocked intent")
            matches.append(item["CommandId"])
        token = response.get("NextToken")
        if not token:
            break
    require(len(matches) == 1, "SSM history does not prove exactly one submission; retain the intent and resume later")
    record.update(commandId=matches[0], submissionState="COMMAND_IDENTIFIED")
    private_save(ROOT / "verify-execute-intent.json", record)
    return {"commandId": matches[0], "ssmStatus": "FOUND", "next": "poll this exact CommandId; never resubmit execute"}


def fresh_evidence(route_script, mode):
    require(hashlib.sha256(route_script.read_bytes()).hexdigest() == ROUTE_SHA256, "Cloud routing adapter checksum differs")
    spec = importlib.util.spec_from_file_location("reviewed_standalone_route", route_script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with open(ROOT / "verify-standalone-source.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        operation = module.Operation()
        value = operation.ready() if mode == "prepare" else operation.verify()
    expected = "STANDALONE_SOURCE_TASK_READY" if mode == "prepare" else "SOURCE_HTTP_DRAIN_AND_WRITER_NETWORK_VERIFIED"
    require(value.get("status") == expected, "The actual AWS source/drain proof is not ready: " + value.get("status", "unknown"))
    return value


def poll(ssm, identifier):
    end = time.monotonic() + 45
    while time.monotonic() < end:
        try:
            response = ssm.get_command_invocation(CommandId=identifier, InstanceId=INSTANCE)
        except ssm.exceptions.InvocationDoesNotExist:
            time.sleep(1)
            continue
        if response["Status"] in ("Pending", "InProgress", "Delayed"):
            time.sleep(1)
            continue
        try:
            result = json.loads(response.get("StandardOutputContent", ""))
        except ValueError:
            result = {"status": "SSM_OUTPUT_REQUIRES_PRIVATE_REVIEW"}
        value = {"commandId": identifier, "ssmStatus": response["Status"], "responseCode": response.get("ResponseCode"), "result": result}
        private_save(ROOT / ("verify-glue-command-" + identifier + ".json"), value)
        if (ROOT / "verify-execute-intent.json").exists():
            record = pending_execution()
            if record.get("commandId") == identifier:
                record["lastObservedResult"] = value
                private_save(ROOT / "verify-execute-intent.json", record)
        if response["Status"] == "Success" and response.get("ResponseCode") == 0 and result.get("status") == "REHEARSAL_PASSED":
            private_save(REHEARSAL, result)
        return value
    return {"commandId": identifier, "ssmStatus": "PENDING", "next": "poll this exact CommandId; do not resubmit"}


def operate(args, ssm):
    if args.operation == "poll":
        require(args.command_id, "Supply the existing CommandId")
        return poll(ssm, args.command_id)
    if args.operation == "resume-execute":
        record = pending_execution()
        return poll(ssm, record["commandId"]) if record.get("commandId") else discover_execution(ssm, record)
    if args.operation == "execute":
        require(not (ROOT / "verify-execute-intent.json").exists(),
                "An execute intent already exists; use resume-execute or poll, never submit another execute")
    payload = {"mode": args.operation, "intentId": uuid.uuid4().hex}
    if args.operation in ("prepare", "execute"):
        require(args.route_script, "Supply the exact reviewed standalone routing script path")
        if args.operation == "execute":
            payload["rehearsal"] = read_rehearsal_record()
        payload["evidence"] = fresh_evidence(args.route_script, args.operation)
    private_save(ROOT / ("verify-glue-intent-" + payload["intentId"] + ".json"), payload)
    command = command_for(payload)
    record = reserve_execution(payload, command) if args.operation == "execute" else None
    print(json.dumps({"intentId": payload["intentId"], "operation": args.operation,
                      "status": "SUBMISSION_INTENT_SAVED"}), flush=True)
    response = ssm.send_command(InstanceIds=[INSTANCE], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [command], "executionTimeout": ["180"]},
        Comment="Verify guarded " + args.operation + " " + payload["intentId"])
    identifier = response["Command"]["CommandId"]
    private_save(ROOT / ("verify-glue-intent-" + payload["intentId"] + ".json"), {**payload, "commandId": identifier})
    if record is not None:
        record.update(commandId=identifier, submissionState="COMMAND_IDENTIFIED")
        private_save(ROOT / "verify-execute-intent.json", record)
    print(json.dumps({"commandId": identifier, "intentId": payload["intentId"], "operation": args.operation}), flush=True)
    return poll(ssm, identifier)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "rehearse", "execute", "poll", "resume-execute"))
    parser.add_argument("--route-script", type=Path)
    parser.add_argument("--command-id")
    args = parser.parse_args()
    try:
        import boto3
        from botocore.config import Config
        options = Config(connect_timeout=3, read_timeout=8, retries={"max_attempts": 0})
        require(boto3.client("sts", config=options).get_caller_identity()["Account"] == ACCOUNT, "Cloud account mismatch")
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(ROOT.stat().st_uid == os.getuid() and not ROOT.stat().st_mode & 0o077, "Cloud evidence directory is not private")
        ssm = boto3.client("ssm", region_name=REGION, config=options)
        with open(ROOT / "verify-ssm-glue.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = operate(args, ssm)
        print(json.dumps(result))
        return 0 if result.get("ssmStatus") in ("Success", "PENDING", "FOUND") and result.get("responseCode", 0) == 0 else 2
    except Exception as error:
        print(json.dumps({"status": "CLOUD_SSM_GLUE_BLOCKED", "errorClass": type(error).__name__,
                          "reason": str(error) if type(error) is RuntimeError else "Inspect private intent/command evidence; do not blindly resubmit"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
