#!/usr/bin/env python3
"""CloudShell gates for the exact Verify source task, RDS and recovery reads.

Every destructive step requires a fresh, independently hashed post-backup target
proof plus a new read-only target authority check. Before-state and each mutation
intent are downloaded-and-hashed versioned S3 objects. This helper never changes
DNS, ALB, NAT, routes, subnets, the target, or the source admission fence.
"""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import time
import uuid

ACCOUNT = "842676017161"
REGION = "us-west-2"
INSTANCE = "i-0e3509a6723d2c0c5"
VPC = "vpc-039a6508764a9d2b3"
SUBNET = "subnet-0486ef164e8819fa9"
TARGET_SG = "sg-0d0af838e410d73da"
TARGET_EIP = "eipalloc-07c3243b98721f6d4"
ROLE = "verify-ledger-minimal-20261114"
READ_POLICY = "VerifyRecoveryReadOnly"
BUCKET = "verify-ledger-migration-842676017161-20261114"
DB = CLUSTER = SERVICE = "verify-ledger"
DB_ARN = "arn:aws:rds:us-west-2:842676017161:db:verify-ledger"
SOURCE_HOST = "verify-ledger.cjcos4w8eowk.us-west-2.rds.amazonaws.com"
SOURCE_SG = "sg-0c32da8357326fd75"
DB_SG = "sg-065d1882bb4a8f8a6"
TD = "arn:aws:ecs:us-west-2:842676017161:task-definition/verify-ledger:1"
IMAGE = "sha256:9e67c0dd5340e4619513f539037b831406225e101ea910dcb1caaf7c7afc48b2"
PROOF_SHA = "ee64786f4587f4417b45faeca6ed0ad5784c25fbe4079a6bacdb0bd2405111dc"
PARAMETERS = tuple("/verify-ledger/infra/" + name for name in
                   ("runtime-db-password", "maintenance-db-password", "export-key", "backup-cipher-key"))
ROOT = Path.home() / "aws-project-migrations-20261114"
STATE_KEY = "live/verify-ledger/retirement/20261114/source-state.json"
ROUTING_KEY = "live/verify-ledger/routing/standalone-source-20261114/current-state.json"
OPERATION = "VERIFY_SOURCE_RETIREMENT_20261114"


class Blocked(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def now():
    return datetime.now(timezone.utc).isoformat()


def encoded(value):
    return (json.dumps(value, indent=2, default=lambda item: item.isoformat() if isinstance(item, datetime) else str(item)) + "\n").encode()


def private(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(encoded(value)); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_private(path):
    require(path.is_file() and path.stat().st_uid == os.getuid() and not path.stat().st_mode & 0o077,
            "Evidence must be a private file owned by this CloudShell user")
    return path.read_bytes()


def check_proof(value, require_source=True):
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(value["capturedAtUtc"])).total_seconds()
    require(0 <= age <= 300 and value.get("status") == "TARGET_LIVE_READ_ONLY_PROOF_PASSED"
            and value.get("accountId") == ACCOUNT and value.get("instanceId") == INSTANCE,
            "A fresh successful exact-target proof is required")
    gate = value.get("bridge", {})
    require(gate.get("mode") == "target" and gate.get("targetActivated") is True
            and gate.get("queueTimeouts") == 0 and gate.get("queued") == 0,
            "Proof does not establish healthy durable TARGET authority")
    require(value.get("latestFullBackup", {}).get("startedAfterCutover") is True
            and value.get("targetDatabase", {}).get("chainsOk") is True
            and value.get("targetDatabase", {}).get("readOnlyConsistentSnapshot") is True,
            "A completed post-cutover full backup and consistent ledger proof are required")
    material = value.get("recoveryMaterial", {})
    expected = {name.rsplit("/", 1)[1] for name in PARAMETERS}
    recovered = material.get("recoveryParameters", {})
    require(set(recovered) == expected and all(item.get("decryptedAndByteMatched") is True for item in recovered.values())
            and material.get("finalDump", {}).get("downloadedAndHashed") is True,
            "The final dump and all four independent recovery values must be verified")
    if require_source:
        source = value.get("sourceFence", {})
        require(source.get("checked") is True and source.get("admissionAllowed") is False
                and source.get("remainingVerifySessions") == 0 and source.get("sourceHost") == SOURCE_HOST,
                "A fresh source admission/session fence proof is required")
    return value


def recovery_policy(keys):
    resources = ["arn:aws:ssm:" + REGION + ":" + ACCOUNT + ":parameter" + name for name in PARAMETERS]
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "ExactRecoveryValues", "Effect": "Allow", "Action": "ssm:GetParameter", "Resource": resources},
        {"Sid": "ExactRecoveryDecryption", "Effect": "Allow", "Action": "kms:Decrypt", "Resource": sorted(keys),
         "Condition": {"StringEquals": {"kms:ViaService": "ssm." + REGION + ".amazonaws.com",
                                         "kms:EncryptionContext:PARAMETER_ARN": resources}}}]}


def delete_arguments():
    # The final logical dump plus tested target physical recovery are required;
    # retain existing automated history without adding an indefinite manual copy.
    return {"DBInstanceIdentifier": DB, "SkipFinalSnapshot": True, "DeleteAutomatedBackups": False}


class Retirement:
    def __init__(self, proof_file=None, proof_sha256=None):
        import boto3
        from botocore.config import Config
        options = Config(connect_timeout=3, read_timeout=8, retries={"max_attempts": 0})
        self.clients = {name: boto3.client(name, region_name=REGION, config=options) for name in
                        ("sts", "s3", "ssm", "ecs", "rds", "ec2", "iam", "kms", "application-autoscaling")}
        require(self.clients["sts"].get_caller_identity()["Account"] == ACCOUNT, "AWS account mismatch")
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(ROOT.stat().st_uid == os.getuid() and not ROOT.stat().st_mode & 0o077, "Private CloudShell directory required")
        require(self.clients["s3"].get_bucket_versioning(Bucket=BUCKET, ExpectedBucketOwner=ACCOUNT).get("Status") == "Enabled",
                "Recovery bucket versioning is required")
        self.proof_file, self.proof_sha256 = proof_file, proof_sha256

    def proof(self, require_source=True):
        require(self.proof_file and self.proof_sha256, "Supply the exact private target proof and its independent SHA256")
        raw = load_private(self.proof_file)
        require(hashlib.sha256(raw).hexdigest() == self.proof_sha256, "Target proof checksum mismatch")
        return check_proof(json.loads(raw), require_source)

    def read_object(self, key, version=None):
        arguments = {"Bucket": BUCKET, "Key": key, "ExpectedBucketOwner": ACCOUNT}
        if version:
            arguments["VersionId"] = version
        response = self.clients["s3"].get_object(**arguments)
        try:
            require(0 < response["ContentLength"] <= 4*1024**2 and response.get("ServerSideEncryption") == "AES256",
                    "Private evidence object size/encryption mismatch")
            raw = response["Body"].read(4*1024**2+1)
        finally:
            response["Body"].close()
        require(len(raw) == response["ContentLength"] and response.get("VersionId") not in (None, "", "null"),
                "Evidence is incomplete or unversioned")
        if version:
            require(response["VersionId"] == version, "Evidence object version mismatch")
        return raw, response

    def archive(self, label, value):
        raw = encoded(value)
        key = "live/verify-ledger/retirement/20261114/" + uuid.uuid4().hex + "/" + label + ".json"
        result = self.clients["s3"].put_object(Bucket=BUCKET, Key=key, Body=raw, ServerSideEncryption="AES256",
            StorageClass="STANDARD", ExpectedBucketOwner=ACCOUNT,
            ChecksumSHA256=base64.b64encode(hashlib.sha256(raw).digest()).decode())
        require(result.get("VersionId") not in (None, "", "null"), "Before-state was not versioned")
        saved, _ = self.read_object(key, result["VersionId"])
        require(saved == raw, "Downloaded before-state differs")
        reference = {"bucket": BUCKET, "key": key, "versionId": result["VersionId"], "sha256": hashlib.sha256(raw).hexdigest()}
        private(ROOT / ("verify-retirement-" + label + ".json"), {"reference": reference, "value": value})
        return reference

    def state(self):
        value = json.loads(load_private(ROOT / "verify-retirement-state.json"))
        remote, response = self.read_object(STATE_KEY)
        require(json.loads(remote) == {key: item for key, item in value.items() if not key.startswith("_s3")},
                "Remote retirement state changed; reconcile private evidence before any retry")
        require(value.get("operationId") == OPERATION and value.get("accountId") == ACCOUNT
                and value.get("instanceId") == INSTANCE, "Wrong retirement operation")
        value.update(_s3Etag=response["ETag"], _s3VersionId=response["VersionId"])
        return value

    def save(self, value):
        value["updatedAtUtc"] = now()
        raw = encoded({key: item for key, item in value.items() if not key.startswith("_s3")})
        condition = {"IfMatch": value["_s3Etag"]} if value.get("_s3Etag") else {"IfNoneMatch": "*"}
        result = self.clients["s3"].put_object(Bucket=BUCKET, Key=STATE_KEY, Body=raw, ServerSideEncryption="AES256",
            StorageClass="STANDARD", ExpectedBucketOwner=ACCOUNT, **condition)
        saved, response = self.read_object(STATE_KEY, result.get("VersionId"))
        require(saved == raw, "Saved retirement state verification failed")
        value.update(_s3Etag=response["ETag"], _s3VersionId=response["VersionId"])
        private(ROOT / "verify-retirement-state.json", value)

    def sync_state(self):
        raw, response = self.read_object(STATE_KEY)
        value = json.loads(raw)
        require(value.get("operationId") == OPERATION and value.get("accountId") == ACCOUNT
                and value.get("instanceId") == INSTANCE, "Remote retirement state identity differs")
        value.update(_s3Etag=response["ETag"], _s3VersionId=response["VersionId"])
        private(ROOT / "verify-retirement-state.json", value)
        return {"status": "RETIREMENT_STATE_RECOVERED_READ_ONLY", "phase": value["phase"], "stateVersionId": value["_s3VersionId"]}

    def target(self):
        rows = [item for reservation in self.clients["ec2"].describe_instances(InstanceIds=[INSTANCE])["Reservations"]
                for item in reservation["Instances"]]
        require(len(rows) == 1, "Target instance identity is ambiguous")
        item = rows[0]
        require(item["State"]["Name"] == "running" and item["VpcId"] == VPC and item["SubnetId"] == SUBNET
                and {group["GroupId"] for group in item["SecurityGroups"]} == {TARGET_SG}
                and item["IamInstanceProfile"]["Arn"] == "arn:aws:iam::" + ACCOUNT + ":instance-profile/" + ROLE,
                "Protected target identity or network changed")
        addresses = self.clients["ec2"].describe_addresses(AllocationIds=[TARGET_EIP])["Addresses"]
        require(len(addresses) == 1 and addresses[0].get("InstanceId") == INSTANCE
                and addresses[0].get("PublicIp") == "44.231.186.126", "Protected target EIP changed")
        profile = self.clients["iam"].get_instance_profile(InstanceProfileName=ROLE)["InstanceProfile"]
        require([role["RoleName"] for role in profile["Roles"]] == [ROLE], "Target instance profile changed")
        return {"instance": item, "eip": addresses[0], "profile": profile}

    def quick_target_gate(self):
        # This is a fixed read-only command. Failure or a slow SSM delivery blocks
        # retirement; it does not alter routing, admission or the running app.
        program = "\n".join([
            "import hashlib,json,os", "from pathlib import Path",
            "p=Path('/opt/verify/current/hosted/lightsail/prove_live_target.py')",
            "assert hashlib.sha256(p.read_bytes()).hexdigest()==" + repr(PROOF_SHA),
            "from hosted.lightsail.prove_live_target import gate_snapshot,runtime_login,source_fence",
            "print(json.dumps({'status':'TARGET_RETIREMENT_GATE_PASSED','bridge':gate_snapshot(),'runtime':runtime_login(),'sourceFence':source_fence()}))"])
        command = "PYTHONPATH=/opt/verify/current/src:/opt/verify/current /opt/verify/current/.venv/bin/python - <<'VERIFY_RETIREMENT_READ_ONLY'\n" + program + "\nVERIFY_RETIREMENT_READ_ONLY"
        identifier = self.clients["ssm"].send_command(InstanceIds=[INSTANCE], DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command], "executionTimeout": ["35"]}, Comment="Verify read-only retirement authority gate")["Command"]["CommandId"]
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                result = self.clients["ssm"].get_command_invocation(CommandId=identifier, InstanceId=INSTANCE)
            except self.clients["ssm"].exceptions.InvocationDoesNotExist:
                time.sleep(.5); continue
            if result["Status"] in ("Pending", "InProgress", "Delayed"):
                time.sleep(.5); continue
            require(result["Status"] == "Success" and result.get("ResponseCode") == 0,
                    "Read-only target authority gate failed; inspect SSM " + identifier)
            proof = json.loads(result["StandardOutputContent"])
            require(proof.get("status") == "TARGET_RETIREMENT_GATE_PASSED"
                    and proof.get("bridge", {}).get("mode") == "target" and proof["bridge"].get("targetActivated") is True
                    and proof.get("sourceFence", {}).get("admissionAllowed") is False
                    and proof["sourceFence"].get("remainingVerifySessions") == 0
                    and proof.get("runtime", {}).get("role") == "verify_runtime"
                    and proof["runtime"].get("readOnlyLoginPassed") is True, "Target gate response mismatch")
            return {**proof, "ssmCommandId": identifier}
        raise Blocked("Read-only target authority gate pending; inspect SSM " + identifier + "; no retirement action was taken")

    def source(self):
        raw, remote = self.read_object(ROUTING_KEY)
        route = json.loads(raw)
        require(route.get("operationId") == "VERIFY_STANDALONE_SOURCE_20261114" and route.get("accountId") == ACCOUNT
                and route.get("instanceId") == INSTANCE and route.get("phase") == "DRAIN_VERIFIED",
                "The corrected source drain must remain verified")
        response = self.clients["ecs"].describe_services(cluster=CLUSTER, services=[SERVICE])
        require(not response.get("failures") and len(response["services"]) == 1, "Source service is missing or ambiguous")
        service = response["services"][0]
        require(service["taskDefinition"] == TD and all(service.get(key) == 0 for key in ("desiredCount", "runningCount", "pendingCount")),
                "Original source service must remain at zero with no pending process")
        scalable = self.clients["application-autoscaling"].describe_scalable_targets(ServiceNamespace="ecs", ResourceIds=["service/" + CLUSTER + "/" + SERVICE])
        require(not scalable.get("ScalableTargets"), "Source ECS scaling automation remains configured")
        tasks = self.clients["ecs"].describe_tasks(cluster=CLUSTER, tasks=[route["standaloneTaskArn"]])
        require(not tasks.get("failures") and len(tasks["tasks"]) == 1, "Pinned standalone task cannot be verified")
        task = tasks["tasks"][0]
        require(task["taskArn"] == route["standaloneTaskArn"] and task["taskDefinitionArn"] == TD
                and task.get("group") == "family:verify-ledger" and task.get("startedBy") == route["standaloneStartedBy"]
                and len(task.get("containers", [])) == 1 and task["containers"][0].get("imageDigest") == IMAGE,
                "Standalone task revision or identity changed")
        active = set()
        for desired in ("RUNNING", "PENDING"):
            for page in self.clients["ecs"].get_paginator("list_tasks").paginate(cluster=CLUSTER, desiredStatus=desired):
                active.update(page["taskArns"])
        require(active <= {task["taskArn"]}, "An unreviewed source cluster task exists")
        interfaces = [item for page in self.clients["ec2"].get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "group-id", "Values": [SOURCE_SG]}]) for item in page["NetworkInterfaces"]]
        expected_eni = route["standalone"]["networkInterfaceId"]
        require({item["NetworkInterfaceId"] for item in interfaces} <= {expected_eni}
                and all(item["VpcId"] == VPC for item in interfaces), "An unexpected client shares the source application group")
        return {"routingStateVersionId": remote["VersionId"], "routingStateSha256": hashlib.sha256(raw).hexdigest(),
                "service": service, "standalone": task, "activeTaskArns": sorted(active),
                "sourceInterfaces": interfaces,
                "sourceSecurityGroups": self.clients["ec2"].describe_security_groups(GroupIds=[SOURCE_SG, DB_SG])["SecurityGroups"],
                "taskDefinition": self.clients["ecs"].describe_task_definition(taskDefinition=TD)["taskDefinition"]}

    def database(self):
        try:
            values = self.clients["rds"].describe_db_instances(DBInstanceIdentifier=DB)["DBInstances"]
        except self.clients["rds"].exceptions.DBInstanceNotFoundFault:
            return None
        require(len(values) == 1, "Source RDS identity is ambiguous")
        value = values[0]
        require(value["DBInstanceArn"] == DB_ARN and value["Engine"] == "postgres" and value["DBName"] == "verify"
                and value.get("MasterUsername") == "verify_owner" and value["Endpoint"]["Address"] == SOURCE_HOST
                and value["DBSubnetGroup"]["VpcId"] == VPC and value.get("PubliclyAccessible") is False
                and value.get("StorageEncrypted") is True and value.get("BackupRetentionPeriod") == 7
                and {row["VpcSecurityGroupId"] for row in value["VpcSecurityGroups"]} == {DB_SG},
                "Source RDS identity, isolation, encryption or existing retention differs")
        require(not value.get("DBClusterIdentifier") and not value.get("ReadReplicaSourceDBInstanceIdentifier")
                and not value.get("ReadReplicaDBInstanceIdentifiers") and not value.get("ReadReplicaDBClusterIdentifiers"),
                "An unreviewed source cluster or read-replica dependency exists")
        return value

    def automated(self, resource_id):
        values = self.clients["rds"].describe_db_instance_automated_backups(DbiResourceId=resource_id)["DBInstanceAutomatedBackups"]
        require(len(values) == 1 and values[0].get("DbiResourceId") == resource_id
                and values[0].get("DBInstanceArn") == DB_ARN and values[0].get("Encrypted") is True
                and values[0].get("BackupRetentionPeriod") == 7 and values[0].get("RestoreWindow", {}).get("EarliestTime")
                and values[0].get("RestoreWindow", {}).get("LatestTime"), "Existing automated recovery history is incomplete")
        key = self.clients["kms"].describe_key(KeyId=values[0]["KmsKeyId"])["KeyMetadata"]
        require(key.get("Arn") == values[0]["KmsKeyId"] and key["Arn"].startswith("arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/")
                and key.get("KeyState") == "Enabled" and not key.get("DeletionDate"),
                "Source recovery encryption key is not enabled or is pending deletion")
        return values[0]

    def policies(self):
        iam = self.clients["iam"]
        names = [name for page in iam.get_paginator("list_role_policies").paginate(RoleName=ROLE) for name in page["PolicyNames"]]
        return {name: iam.get_role_policy(RoleName=ROLE, PolicyName=name)["PolicyDocument"] for name in names}

    def recovery_parameters(self):
        keys, metadata = set(), []
        for name in PARAMETERS:
            rows = self.clients["ssm"].describe_parameters(ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}])["Parameters"]
            require(len(rows) == 1 and rows[0]["Name"] == name and rows[0]["Type"] == "SecureString",
                    "Exact recovery parameter metadata is missing")
            key = self.clients["kms"].describe_key(KeyId=rows[0]["KeyId"])["KeyMetadata"]
            require(key["Arn"].startswith("arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/")
                    and key["KeyState"] == "Enabled" and key["KeyUsage"] == "ENCRYPT_DECRYPT",
                    "Recovery encryption key is not enabled in this account/region")
            keys.add(key["Arn"]); metadata.append({"parameter": rows[0], "key": key})
        return keys, metadata

    def permanent_recovery(self):
        target = self.target(); before = self.policies(); keys, metadata = self.recovery_parameters()
        desired = recovery_policy(keys)
        require(READ_POLICY not in before or before[READ_POLICY] == desired, "An existing permanent policy differs; inspect before replacing")
        backup = self.archive("recovery-policy-before", {"capturedAtUtc": now(), "target": target, "inlinePolicies": before,
                                                        "parameters": metadata, "intendedPolicy": desired})
        self.clients["iam"].put_role_policy(RoleName=ROLE, PolicyName=READ_POLICY, PolicyDocument=json.dumps(desired))
        require(self.clients["iam"].get_role_policy(RoleName=ROLE, PolicyName=READ_POLICY)["PolicyDocument"] == desired,
                "Permanent recovery policy was not read back exactly")
        return {"status": "EXACT_PERMANENT_RECOVERY_READS_CONFIGURED", "policyName": READ_POLICY, "beforeState": backup,
                "parameterCount": 4, "writePermissionsAdded": False, "temporaryGrantsRemoved": False,
                "next": "Run the target recovery-value proof again; remove temporary grants only after retirement verification"}

    def capture(self):
        proof = self.proof(); target = self.target(); source = self.source(); database = self.database()
        require(database and database["DBInstanceStatus"] == "available", "Capture requires the original available source database")
        automated = self.automated(database["DbiResourceId"])
        require(automated["KmsKeyId"] == database["KmsKeyId"], "Source automated backup encryption key differs")
        policies = self.policies(); keys, metadata = self.recovery_parameters()
        require(policies.get(READ_POLICY) == recovery_policy(keys), "Configure exact permanent recovery reads before source retirement")
        gate = self.quick_target_gate(); self.proof()
        before = {"capturedAtUtc": now(), "target": target, "source": source, "database": database,
                  "automatedBackup": automated, "targetProof": proof, "targetProofSha256": self.proof_sha256,
                  "targetGate": gate, "targetInlinePolicies": policies, "recoveryParameters": metadata,
                  "deleteArguments": delete_arguments()}
        reference = self.archive("before-source-retirement", before)
        require(not (ROOT / "verify-retirement-state.json").exists(), "Retirement already has a durable state; use status and the existing operation")
        state = {"operationId": OPERATION, "accountId": ACCOUNT, "instanceId": INSTANCE, "phase": "BEFORE_STATE_SAVED",
                 "before": reference, "dbiResourceId": database["DbiResourceId"], "kmsKeyId": database["KmsKeyId"],
                 "standaloneTaskArn": source["standalone"]["taskArn"], "cutoverReportSha256": proof["cutoverReportSha256"],
                 "createdAtUtc": now()}
        self.save(state)
        return {"status": "SOURCE_RETIREMENT_BEFORE_STATE_VERIFIED", "beforeState": reference,
                "dbiResourceId": state["dbiResourceId"], "stateVersionId": state["_s3VersionId"]}

    def checked_state(self):
        state = self.state(); proof = self.proof()
        require(proof["cutoverReportSha256"] == state["cutoverReportSha256"], "Target proof belongs to another cutover")
        raw, _ = self.read_object(state["before"]["key"], state["before"]["versionId"])
        require(hashlib.sha256(raw).hexdigest() == state["before"]["sha256"], "Pinned before-state checksum changed")
        self.target()
        keys, _ = self.recovery_parameters()
        require(self.policies().get(READ_POLICY) == recovery_policy(keys), "Exact permanent recovery-read policy changed before retirement")
        return state

    def stop_source(self):
        state = self.checked_state(); source = self.source(); task = source["standalone"]
        require(task["taskArn"] == state["standaloneTaskArn"], "Source task no longer matches saved before-state")
        gate = self.quick_target_gate(); self.proof()
        if task["lastStatus"] == "STOPPED":
            require(not source["activeTaskArns"], "A source task remains active")
            state.update(phase="SOURCE_TASK_STOPPED", sourceStoppedAtUtc=now(), sourceStoppedEvidence=source)
            self.save(state)
            return {"status": "SOURCE_STANDALONE_STOPPED", "taskArn": task["taskArn"], "stateVersionId": state["_s3VersionId"]}
        if task.get("desiredStatus") == "STOPPED":
            return {"status": "SOURCE_TASK_STOP_PENDING", "taskArn": task["taskArn"], "lastStatus": task["lastStatus"]}
        require(task["lastStatus"] == "RUNNING", "Source task state requires review")
        intent = self.archive("stop-source-intent", {"capturedAtUtc": now(), "before": source, "targetGate": gate,
                                                    "targetProofSha256": self.proof_sha256, "taskArn": task["taskArn"]})
        state.update(phase="SOURCE_TASK_STOP_INTENT", stopIntent=intent); self.save(state)
        self.clients["ecs"].stop_task(cluster=CLUSTER, task=task["taskArn"], reason="Verified authoritative target and independent post-cutover backup")
        return {"status": "SOURCE_TASK_STOP_REQUESTED", "taskArn": task["taskArn"], "intent": intent,
                "next": "Run stop-source again to observe STOPPED; never change source admission"}

    def delete_rds(self):
        state = self.state(); database = self.database()
        if database is None or database["DBInstanceStatus"] == "deleting":
            return self.status()
        state = self.checked_state(); source = self.source()
        require(source["standalone"]["taskArn"] == state["standaloneTaskArn"]
                and source["standalone"]["lastStatus"] == "STOPPED" and not source["activeTaskArns"],
                "All source processes must be stopped before RDS deletion")
        require(database["DbiResourceId"] == state["dbiResourceId"] and database["KmsKeyId"] == state["kmsKeyId"]
                and database["DBInstanceStatus"] == "available", "Source database identity/state changed")
        history = self.automated(state["dbiResourceId"])
        require(history["KmsKeyId"] == state["kmsKeyId"], "Source automated backup no longer uses the saved encryption key")
        gate = self.quick_target_gate(); self.proof()
        before = {"capturedAtUtc": now(), "database": database, "automatedBackup": history, "source": source,
                  "targetGate": gate, "targetProofSha256": self.proof_sha256, "deleteArguments": delete_arguments()}
        if database.get("DeletionProtection"):
            intent = self.archive("remove-source-deletion-protection-intent", before)
            state.update(phase="RDS_PROTECTION_REMOVAL_INTENT", protectionIntent=intent); self.save(state)
            self.proof()
            current = self.database()
            require(current and current["DbiResourceId"] == state["dbiResourceId"]
                    and current["DBInstanceStatus"] == "available" and current.get("DeletionProtection") is True,
                    "Source identity/protection changed before the exact modification")
            self.clients["rds"].modify_db_instance(DBInstanceIdentifier=DB, DeletionProtection=False, ApplyImmediately=True)
            return {"status": "SOURCE_RDS_PROTECTION_REMOVAL_REQUESTED", "intent": intent,
                    "next": "Recheck available/source identity and rerun delete-rds with a fresh target proof"}
        intent = self.archive("delete-source-rds-intent", before)
        state.update(phase="RDS_DELETE_INTENT", deleteIntent=intent); self.save(state)
        self.proof()
        current = self.database()
        require(current and current["DbiResourceId"] == state["dbiResourceId"]
                and current["DBInstanceStatus"] == "available" and current.get("DeletionProtection") is False,
                "Source identity/protection changed before deletion")
        self.clients["rds"].delete_db_instance(**delete_arguments())
        return {"status": "SOURCE_RDS_DELETION_REQUESTED", "intent": intent, "DeleteAutomatedBackups": False,
                "next": "Poll status by the saved DbiResourceId; preserve its KMS key and existing restore window"}

    def status(self):
        state = self.state(); self.target(); database = self.database()
        if database is not None:
            require(database["DbiResourceId"] == state["dbiResourceId"], "A different database reused the source identifier")
            return {"status": "SOURCE_RDS_STILL_PRESENT", "databaseStatus": database["DBInstanceStatus"],
                    "deletionProtection": database.get("DeletionProtection"), "phase": state["phase"]}
        require(state.get("deleteIntent"), "Source is missing without this operation's pinned deletion intent")
        history = self.automated(state["dbiResourceId"])
        require(history.get("Status") == "retained" and history.get("KmsKeyId") == state["kmsKeyId"],
                "Deleted source automated backup is not yet retained with the same encryption key")
        source = self.source()
        require(source["standalone"]["lastStatus"] == "STOPPED" and not source["activeTaskArns"], "Source processes reappeared")
        journal = {"status": "VERIFY_SOURCE_TASK_AND_RDS_RETIRED", "capturedAtUtc": now(), "accountId": ACCOUNT,
                   "instanceId": INSTANCE, "sourceRdsAbsent": True, "dbiResourceId": state["dbiResourceId"],
                   "standaloneTaskArn": state["standaloneTaskArn"], "standaloneStopped": True,
                   "managedDesiredCount": 0, "managedRunningCount": 0, "managedPendingCount": 0,
                   "retainedAutomatedBackup": history, "sourceBeforeState": state["before"],
                   "deleteIntent": state["deleteIntent"], "cutoverReportSha256": state["cutoverReportSha256"],
                   "preservedTarget": {"instanceId": INSTANCE, "vpcId": VPC, "subnetId": SUBNET,
                                       "securityGroupId": TARGET_SG, "eipAllocationId": TARGET_EIP},
                   "networkResourcesDeleted": False,
                   "scope": "Existing source backup history ages out under its prior window; no new seven-day history is promised"}
        reference = self.archive("source-retirement-verified", journal)
        state.update(phase="SOURCE_TASK_AND_RDS_RETIRED", finalJournal=reference); self.save(state)
        return {"status": journal["status"], "journal": reference, "restoreWindow": history["RestoreWindow"],
                "next": "Run source-free target proof, then separately reviewed DNS/ALB/NAT cleanup and temporary-grant removal"}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("recovery-read", "capture", "stop-source", "delete-rds", "status", "sync-state"))
    parser.add_argument("--proof-file", type=Path)
    parser.add_argument("--proof-sha256")
    args = parser.parse_args()
    try:
        task = Retirement(args.proof_file, args.proof_sha256)
        with open(ROOT / "verify-retirement.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            function = {"recovery-read": task.permanent_recovery, "capture": task.capture, "stop-source": task.stop_source,
                        "delete-rds": task.delete_rds, "status": task.status, "sync-state": task.sync_state}[args.operation]
            print(json.dumps(function(), default=str))
        return 0
    except Exception as error:
        print(json.dumps({"status": "SOURCE_RETIREMENT_BLOCKED", "errorClass": type(error).__name__,
                          "reason": str(error) if isinstance(error, Blocked) else "Inspect private intent and fresh AWS state; credential details suppressed",
                          "recovery": "Keep TARGET authoritative and source fenced; never restore the stale source database"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
