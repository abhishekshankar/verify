#!/usr/bin/env python3
"""Guarded CloudShell SOURCE handover, ALB connection drain, and rollback evidence.

This script never changes DNS, database data/admission, application writer state,
source desiredCount, task definitions, or source images. It temporarily extends
the existing ECS task's health grace without a deployment, routes new HTTPS calls
through the healthy SOURCE bridge, and explicitly deregisters the old ALB target
using its unchanged delay. verify returns PENDING until AWS reports deregistration
complete. Every operation is bound to this exact pilot and versioned S3 evidence.

Run handover once, then verify after the configured drain. Rollback is permitted
only while the target independently proves SOURCE and has no writer marker.
Rollback re-registers and waits for a healthy old target before restoring routing
and then grace. It never unfences a database or restores a stale source.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import shlex
import socket
import ssl
import tempfile
import time
import uuid

ACCOUNT = "842676017161"
REGION = "us-west-2"
INSTANCE = "i-0e3509a6723d2c0c5"
VPC = "vpc-039a6508764a9d2b3"
TARGET_IP = "10.40.0.249"
TARGET_PUBLIC = "44.231.186.126"
SOURCE_IP = "10.40.11.28"
SOURCE_HOST = "verify-ledger.cjcos4w8eowk.us-west-2.rds.amazonaws.com"
HOSTNAME = "ledger.optimise.work"
SOURCE_IMAGE = "sha256:9e67c0dd5340e4619513f539037b831406225e101ea910dcb1caaf7c7afc48b2"
TASK_DEFINITION = "arn:aws:ecs:us-west-2:842676017161:task-definition/verify-ledger:1"
ALB = "arn:aws:elasticloadbalancing:us-west-2:842676017161:loadbalancer/app/verify-ledger/8c146e0135e79e34"
HTTPS = "arn:aws:elasticloadbalancing:us-west-2:842676017161:listener/app/verify-ledger/8c146e0135e79e34/12730dbcac7c31ee"
SOURCE_TG = "arn:aws:elasticloadbalancing:us-west-2:842676017161:targetgroup/verify-ledger/63e16a3aeef8d276"
ALB_SG = "sg-008efd8aa7abb6352"
SOURCE_SG = "sg-0c32da8357326fd75"
DATABASE_SG = "sg-065d1882bb4a8f8a6"
TARGET_SG = "sg-0d0af838e410d73da"
BUCKET = "verify-ledger-migration-842676017161-20261114"
ROOT = Path.home() / "aws-project-migrations-20261114"
STATE = ROOT / "verify-source-route-state.json"
EXPECTED_TARGET = {"Id": SOURCE_IP, "Port": 8080}


class Blocked(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise Blocked(reason)


def now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return (json.dumps(value, indent=2, default=str) + "\n").encode()


def atomic(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=".route-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encode(value))
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def targets(actions):
    """Normalize actual listener forwarding; duplicate AWS response fields agree."""
    result = {}
    sticky = False
    for action in actions:
        if action["Type"] != "forward":
            continue
        configuration = action.get("ForwardConfig", {})
        groups = configuration.get("TargetGroups") or [{"TargetGroupArn": action.get("TargetGroupArn"), "Weight": 1}]
        for group in groups:
            arn, weight = group.get("TargetGroupArn"), group.get("Weight", 1)
            require(arn and type(weight) is int and 0 <= weight <= 999, "Malformed forwarding action")
            require(arn not in result, "Duplicate target group forwarding entry")
            result[arn] = weight
        sticky = sticky or configuration.get("TargetGroupStickinessConfig", {}).get("Enabled", False)
    return result, sticky


def port_peers(group, port):
    """Include ranges and all-protocol rules; reject public/prefix access."""
    peers, relevant = set(), []
    for rule in group.get("IpPermissions", []):
        protocol = str(rule["IpProtocol"])
        permits = protocol == "-1" or (protocol in ("tcp", "6") and int(rule.get("FromPort", -1)) <= port <= int(rule.get("ToPort", -1)))
        if not permits:
            continue
        require(not rule.get("IpRanges") and not rule.get("Ipv6Ranges") and not rule.get("PrefixListIds"),
                "Unreviewed CIDR or prefix-list reachability on a source service port")
        for pair in rule.get("UserIdGroupPairs", []):
            require(pair.get("UserId", ACCOUNT) == ACCOUNT and pair.get("GroupId"), "Unreviewed cross-account security-group client")
            peers.add(pair["GroupId"])
        relevant.append(rule)
    return peers, relevant


def tls_request(address, path):
    connection = http.client.HTTPConnection(address, 443, timeout=4)
    try:
        raw = socket.create_connection((address, 443), timeout=4)
        connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=HOSTNAME)
        certificate = connection.sock.getpeercert(binary_form=True)
        connection.request("GET", path, headers={"Host": HOSTNAME, "Connection": "close"})
        response = connection.getresponse()
        data = response.read(65537)
        require(len(data) <= 65536, "Unexpected TLS probe body size")
        return {"address": address, "path": path, "status": response.status,
                "certificateSha256": hashlib.sha256(certificate).hexdigest()}, data
    finally:
        connection.close()


class Operation:
    def __init__(self):
        import boto3
        from botocore.config import Config
        options = Config(connect_timeout=3, read_timeout=10, retries={"max_attempts": 1})
        self.clients = {name: boto3.client(name, region_name=REGION, config=options)
                        for name in ("sts", "ec2", "ecs", "rds", "elbv2", "ssm", "s3", "application-autoscaling")}
        require(self.clients["sts"].get_caller_identity()["Account"] == ACCOUNT, "AWS caller account mismatch")
        location = self.clients["s3"].get_bucket_location(Bucket=BUCKET).get("LocationConstraint") or "us-east-1"
        require(location == REGION, "Verified project backup bucket region mismatch")
        require(self.clients["s3"].get_bucket_versioning(Bucket=BUCKET).get("Status") == "Enabled", "Rollback evidence bucket is not versioned")
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not ROOT.stat().st_mode & 0o077 and ROOT.stat().st_uid == os.getuid(), "CloudShell evidence directory must be private")

    def save(self, value, name="state.json"):
        key = "live/verify-ledger/routing/" + value["token"] + "/" + name
        data = encode(value)
        digest = hashlib.sha256(data).digest()
        saved = self.clients["s3"].put_object(Bucket=BUCKET, Key=key, Body=data, ServerSideEncryption="AES256",
                                             ChecksumSHA256=base64.b64encode(digest).decode())
        require(saved.get("VersionId") not in (None, "", "null") and saved.get("ServerSideEncryption") == "AES256",
                "Versioned encrypted rollback evidence was not confirmed")
        location = {"bucket": BUCKET, "key": key, "versionId": saved["VersionId"], "sha256": digest.hex()}
        if name == "state.json":
            atomic(STATE, value)
            atomic(ROOT / "verify-source-route-location.json", location)
        else:
            atomic(ROOT / name, value)
            atomic(ROOT / (name + ".location.json"), location)
        return location

    def target_proof(self, invalidate=False):
        mode = "invalidate" if invalidate else "snapshot"
        command = ("PYTHONPATH=/opt/verify/current/src:/opt/verify/current "
                   "/opt/verify/current/.venv/bin/python -m hosted.lightsail.attest_source_route "
                   + mode + " --source-private-ip " + shlex.quote(SOURCE_IP))
        identifier = self.clients["ssm"].send_command(
            InstanceIds=[INSTANCE], DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command], "executionTimeout": ["40"]},
            Comment="Verify read-only SOURCE writer and bridge routing gate")["Command"]["CommandId"]
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                reply = self.clients["ssm"].get_command_invocation(CommandId=identifier, InstanceId=INSTANCE)
            except self.clients["ssm"].exceptions.InvocationDoesNotExist:
                time.sleep(1)
                continue
            if reply["Status"] in ("Pending", "InProgress", "Delayed"):
                time.sleep(1)
                continue
            require(reply["Status"] == "Success" and reply.get("ResponseCode") == 0,
                    "Target SOURCE attestation failed; inspect the private SSM command " + identifier)
            proof = json.loads(reply["StandardOutputContent"])
            require(proof.get("status") == ("SOURCE_ROUTING_READINESS_INVALIDATED" if invalidate else "SOURCE_WRITER_AND_BRIDGE_VERIFIED")
                    and proof.get("instanceId") == INSTANCE and proof.get("accountId") == ACCOUNT
                    and proof.get("sourcePrivateIp") == SOURCE_IP and proof.get("productionWriterEnabled") is False,
                    "Target SOURCE attestation identity mismatch")
            proof["ssmCommandId"] = identifier
            return proof
        raise Blocked("Target SOURCE attestation remains pending; inspect command " + identifier)

    def task(self):
        ecs = self.clients["ecs"]
        reply = ecs.describe_services(cluster="verify-ledger", services=["verify-ledger"])
        require(not reply.get("failures") and len(reply["services"]) == 1, "Source service not found")
        service = reply["services"][0]
        require(service["status"] == "ACTIVE" and service["desiredCount"] == service["runningCount"] == 1
                and service["pendingCount"] == 0 and service["taskDefinition"] == TASK_DEFINITION,
                "Source ECS service is not the reviewed single running revision")
        deployments = service["deployments"]
        require(len(deployments) == 1 and deployments[0]["status"] == "PRIMARY"
                and deployments[0].get("rolloutState") == "COMPLETED", "Source ECS deployment is changing")
        require(service.get("deploymentController", {}).get("type", "ECS") == "ECS", "Unexpected source deployment controller")
        require(service["loadBalancers"] == [{"targetGroupArn": SOURCE_TG, "containerName": "api", "containerPort": 8080}],
                "Source ECS load-balancer registration differs")
        network = service["networkConfiguration"]["awsvpcConfiguration"]
        require(set(network["securityGroups"]) == {SOURCE_SG} and network.get("assignPublicIp") == "DISABLED",
                "Source ECS network configuration differs")
        arns = []
        for page in ecs.get_paginator("list_tasks").paginate(cluster="verify-ledger", serviceName="verify-ledger", desiredStatus="RUNNING"):
            arns.extend(page["taskArns"])
        require(len(arns) == 1, "Source service has additional running tasks")
        described = ecs.describe_tasks(cluster="verify-ledger", tasks=arns)
        require(not described.get("failures") and len(described["tasks"]) == 1, "Source task unavailable")
        task = described["tasks"][0]
        require(task["lastStatus"] == "RUNNING" and task["desiredStatus"] == "RUNNING"
                and task["taskDefinitionArn"] == TASK_DEFINITION and task.get("startedAt"),
                "Source task changed or is stopping")
        containers = task["containers"]
        require(len(containers) == 1 and containers[0]["name"] == "api" and containers[0]["lastStatus"] == "RUNNING"
                and containers[0].get("imageDigest") == SOURCE_IMAGE, "Source container image identity changed")
        attachments = [item for item in task["attachments"] if item["type"] == "ElasticNetworkInterface"]
        require(len(attachments) == 1 and attachments[0]["status"] == "ATTACHED", "Source ECS network attachment differs")
        details = {item["name"]: item["value"] for item in attachments[0]["details"]}
        require(details.get("privateIPv4Address") == SOURCE_IP, "Source task private address changed")
        return {"taskArn": task["taskArn"], "privateIp": SOURCE_IP, "networkInterfaceId": details["networkInterfaceId"],
                "imageDigest": SOURCE_IMAGE, "startedAt": task["startedAt"].isoformat(),
                "deploymentId": deployments[0]["id"], "taskDefinitionArn": TASK_DEFINITION,
                "desiredCount": 1, "runningCount": 1, "pendingCount": 0,
                "healthCheckGracePeriodSeconds": service.get("healthCheckGracePeriodSeconds", 0),
                "enableExecuteCommand": task.get("enableExecuteCommand", False)}

    def stable_task(self, state):
        task = self.task()
        original = state["before"]["task"]
        require(all(task[key] == original[key] for key in ("taskArn", "privateIp", "networkInterfaceId", "imageDigest", "startedAt", "deploymentId")),
                "Source task/deployment changed; do not continue this handover")
        return task

    def rules(self, bridge, acme):
        lb = self.clients["elbv2"]
        listeners = lb.describe_listeners(LoadBalancerArn=ALB)["Listeners"]
        require({item["Port"] for item in listeners} == {80, 443}, "Unreviewed ALB listener")
        all_rules, https = {}, None
        for listener in listeners:
            require(listener["Protocol"] == ("HTTPS" if listener["Port"] == 443 else "HTTP"), "Listener protocol mismatch")
            rules = lb.describe_rules(ListenerArn=listener["ListenerArn"])["Rules"]
            all_rules[str(listener["Port"])] = rules
            if listener["Port"] == 443:
                require(listener["ListenerArn"] == HTTPS and len(rules) == 1 and rules[0]["IsDefault"],
                        "An HTTPS rule can bypass the reviewed default action")
                require(len(listener["DefaultActions"]) == 1 and listener["DefaultActions"][0]["Type"] == "forward",
                        "HTTPS contains an unreviewed authentication or non-forward action")
                https = listener
            else:
                for rule in rules:
                    forwarded, sticky = targets(rule["Actions"])
                    require(not sticky and set(forwarded) <= {bridge, acme}, "HTTP listener has an unreviewed source forwarding path")
                    require(all(action["Type"] in ("forward", "redirect") for action in rule["Actions"]), "Unreviewed HTTP action")
                    for action in rule["Actions"]:
                        if action["Type"] == "redirect":
                            require(action["RedirectConfig"] == {"Protocol": "HTTPS", "Port": "443", "Host": "#{host}",
                                "Path": "/#{path}", "Query": "#{query}", "StatusCode": "HTTP_301"},
                                "HTTP redirect differs from the existing same-host HTTPS behavior")
        require(https is not None, "Expected HTTPS listener missing")
        return https, all_rules

    def group(self, name, port, require_healthy=True):
        lb = self.clients["elbv2"]
        groups = lb.describe_target_groups(Names=[name])["TargetGroups"]
        require(len(groups) == 1, "Expected bridge target group missing")
        group = groups[0]
        require(group["VpcId"] == VPC and group["TargetType"] == "ip" and group["Protocol"] == "HTTP"
                and group["Port"] == port and group["HealthCheckPort"] == "8082"
                and group["HealthCheckPath"] == "/__migration_health" and group["Matcher"]["HttpCode"] == "200",
                "Target group identity/health configuration differs")
        rows = lb.describe_target_health(TargetGroupArn=group["TargetGroupArn"])["TargetHealthDescriptions"]
        require(len(rows) == 1 and rows[0]["Target"]["Id"] == TARGET_IP and rows[0]["Target"]["Port"] == port,
                "Target group contains unexpected targets")
        if require_healthy:
            require(rows[0]["TargetHealth"]["State"] == "healthy", "Bridge/ACME target group is not healthy; attach and warm it before handover")
        attributes = {item["Key"]: item["Value"] for item in lb.describe_target_group_attributes(TargetGroupArn=group["TargetGroupArn"])["Attributes"]}
        require(attributes.get("stickiness.enabled") == "false", "Target group stickiness must be disabled")
        return group["TargetGroupArn"], rows

    def inventory(self):
        ec, lb = self.clients["ec2"], self.clients["elbv2"]
        task = self.task()
        autoscaling = self.clients["application-autoscaling"].describe_scalable_targets(
            ServiceNamespace="ecs", ResourceIds=["service/verify-ledger/verify-ledger"])["ScalableTargets"]
        require(not autoscaling, "Unreviewed ECS autoscaling can change the source task count")
        dbs = self.clients["rds"].describe_db_instances(DBInstanceIdentifier="verify-ledger")["DBInstances"]
        require(len(dbs) == 1, "Source RDS instance missing")
        db = dbs[0]
        require(db["DBInstanceStatus"] == "available" and db["Engine"] == "postgres" and db["EngineVersion"].startswith("16.")
                and db.get("DBName") == "verify" and db.get("MasterUsername") == "verify_owner"
                and db["Endpoint"]["Address"] == SOURCE_HOST and db["Endpoint"]["Port"] == 5432
                and db.get("PubliclyAccessible") is False and db["DBSubnetGroup"]["VpcId"] == VPC
                and {item["VpcSecurityGroupId"] for item in db["VpcSecurityGroups"]} == {DATABASE_SG}
                and db["BackupRetentionPeriod"] == 7, "Source RDS identity, privacy or retention differs")
        instances = ec.describe_instances(InstanceIds=[INSTANCE])["Reservations"]
        require(len(instances) == 1 and len(instances[0]["Instances"]) == 1, "Target instance missing")
        instance = instances[0]["Instances"][0]
        require(instance["State"]["Name"] == "running" and instance["VpcId"] == VPC
                and instance["PrivateIpAddress"] == TARGET_IP and instance["PublicIpAddress"] == TARGET_PUBLIC
                and {item["GroupId"] for item in instance["SecurityGroups"]} == {TARGET_SG},
                "Target instance/network identity differs")
        groups = {item["GroupId"]: item for item in ec.describe_security_groups(GroupIds=[DATABASE_SG, SOURCE_SG, TARGET_SG, ALB_SG])["SecurityGroups"]}
        require(all(item["VpcId"] == VPC for item in groups.values()), "Security group VPC mismatch")
        database_peers, database_rules = port_peers(groups[DATABASE_SG], 5432)
        app_peers, app_rules = port_peers(groups[SOURCE_SG], 8080)
        require(database_peers == {SOURCE_SG, TARGET_SG} and app_peers == {ALB_SG, TARGET_SG},
                "Additional source database/app network clients exist")
        interfaces = []
        for page in ec.get_paginator("describe_network_interfaces").paginate(Filters=[{"Name": "group-id", "Values": [SOURCE_SG, TARGET_SG, ALB_SG]}]):
            interfaces.extend(page["NetworkInterfaces"])
        by_group = {group: [item for item in interfaces if group in {entry["GroupId"] for entry in item["Groups"]}]
                    for group in (SOURCE_SG, TARGET_SG, ALB_SG)}
        require({item["NetworkInterfaceId"] for item in by_group[SOURCE_SG]} == {task["networkInterfaceId"]}
                and all(item["Status"] == "in-use" and not item.get("Association") for item in by_group[SOURCE_SG]),
                "Additional or publicly associated source application interfaces exist")
        target_enis = {item["NetworkInterfaceId"] for item in instance["NetworkInterfaces"]}
        require({item["NetworkInterfaceId"] for item in by_group[TARGET_SG]} == target_enis
                and len(target_enis) == 1, "Target writer group is shared with another network interface")
        expected_description = "ELB " + ALB.split("loadbalancer/", 1)[1]
        require(by_group[ALB_SG] and all(item["Description"] == expected_description and item["Status"] == "in-use"
                                           for item in by_group[ALB_SG]), "The source ALB group is attached elsewhere")
        source_enis = by_group[SOURCE_SG]
        require(all({entry["GroupId"] for entry in item["Groups"]} == {SOURCE_SG} for item in source_enis),
                "Additional application security groups can bypass the reviewed ingress")
        definition = self.clients["ecs"].describe_task_definition(taskDefinition=TASK_DEFINITION)["taskDefinition"]
        require(definition["runtimePlatform"]["cpuArchitecture"] == "ARM64" and definition["networkMode"] == "awsvpc"
                and len(definition["containerDefinitions"]) == 1, "Source task definition changed")
        container = definition["containerDefinitions"][0]
        environment = {item["name"]: item["value"] for item in container.get("environment", [])}
        require(set(environment) == {"VERIFY_DB_HOST", "VERIFY_DB_NAME", "VERIFY_DB_SSLMODE"}
                and environment["VERIFY_DB_HOST"] == SOURCE_HOST and environment["VERIFY_DB_NAME"] == "verify",
                "Source application database configuration is unreviewed")
        bridge, bridge_health = self.group("verify-bridge-20261114", 8082)
        acme, acme_health = self.group("verify-acme-20261114", 80)
        https, rules = self.rules(bridge, acme)
        load = lb.describe_load_balancers(LoadBalancerArns=[ALB])["LoadBalancers"][0]
        require(load["VpcId"] == VPC and set(load["SecurityGroups"]) == {ALB_SG}, "ALB identity/network mismatch")
        source_group = lb.describe_target_groups(TargetGroupArns=[SOURCE_TG])["TargetGroups"][0]
        require(source_group["VpcId"] == VPC and source_group["TargetType"] == "ip" and source_group["Port"] == 8080,
                "Original source target group differs")
        source_attributes = {item["Key"]: item["Value"] for item in lb.describe_target_group_attributes(TargetGroupArn=SOURCE_TG)["Attributes"]}
        require(source_attributes.get("stickiness.enabled") == "false", "Original target group stickiness is enabled")
        delay = int(source_attributes["deregistration_delay.timeout_seconds"])
        require(0 <= delay <= 3600, "Unexpected original deregistration delay")
        external, body = tls_request(TARGET_PUBLIC, "/v1/verify-chain")
        require(external["status"] == 401 and body.startswith(b'{"error":'), "Target trusted TLS/API probe failed")
        return {"capturedAtUtc": now(), "task": task, "targetInstanceId": INSTANCE, "targetInterfaces": sorted(target_enis),
                "sourceDatabase": {"identifier": "verify-ledger", "endpoint": SOURCE_HOST, "port": 5432,
                    "publiclyAccessible": False, "version": db["EngineVersion"], "backupRetentionDays": 7,
                    "vpcId": VPC, "securityGroup": DATABASE_SG},
                "databaseClientGroups": sorted(database_peers), "databaseIngressRules": database_rules,
                "appClientGroups": sorted(app_peers), "appIngressRules": app_rules,
                "peerInterfaces": {key: [{"id": item["NetworkInterfaceId"], "privateIp": item["PrivateIpAddress"],
                                             "description": item["Description"], "status": item["Status"]} for item in value]
                                   for key, value in by_group.items()},
                "bridgeTargetGroup": bridge, "acmeTargetGroup": acme, "bridgeHealth": bridge_health,
                "acmeHealth": acme_health, "httpsActions": https["DefaultActions"], "rules": rules,
                "albDnsName": load["DNSName"], "sourceDeregistrationDelay": delay, "targetTls": external}

    def handover(self):
        inventory = self.inventory()
        proof = self.target_proof()
        bridge = inventory["bridgeTargetGroup"]
        if STATE.exists():
            state = json.loads(STATE.read_text())
            require(state.get("accountId") == ACCOUNT and state.get("instanceId") == INSTANCE
                    and state.get("phase") != "ROLLED_BACK", "Existing routing state needs review")
            self.stable_task(state)
        else:
            forwarded, sticky = targets(inventory["httpsActions"])
            require(forwarded == {SOURCE_TG: 1} and not sticky, "Initial HTTPS routing is not exclusively the old source")
            registrations = self.clients["elbv2"].describe_target_health(TargetGroupArn=SOURCE_TG)["TargetHealthDescriptions"]
            require(len(registrations) == 1 and registrations[0]["Target"]["Id"] == SOURCE_IP
                    and registrations[0]["Target"]["Port"] == 8080 and registrations[0]["TargetHealth"]["State"] == "healthy",
                    "Original source registration is not exactly the healthy observed task")
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(inventory["task"]["startedAt"])).total_seconds()
            require(0 <= age < 2147476000, "Source task age is invalid")
            grace = max(inventory["task"]["healthCheckGracePeriodSeconds"], math.ceil(age) + 7200)
            state = {"schemaVersion": 1, "token": uuid.uuid4().hex[:12], "accountId": ACCOUNT, "instanceId": INSTANCE,
                     "phase": "BEFORE_SAVED", "createdAtUtc": now(), "before": inventory,
                     "originalRegistrations": registrations, "sourceGateBefore": proof, "migrationGraceSeconds": grace,
                     "bridgeTargetGroup": bridge, "acmeTargetGroup": inventory["acmeTargetGroup"]}
            self.save(state)  # Durable, encrypted, versioned evidence precedes every mutation.
        require(state["bridgeTargetGroup"] == bridge and inventory["sourceDeregistrationDelay"] == state["before"]["sourceDeregistrationDelay"],
                "Routing identity or original drain delay changed")
        if state["phase"] in ("DRAINING", "DRAIN_VERIFIED"):
            return self.verify(state)
        task = self.stable_task(state)
        old_grace = state["before"]["task"]["healthCheckGracePeriodSeconds"]
        require(task["healthCheckGracePeriodSeconds"] in (old_grace, state["migrationGraceSeconds"]), "Source grace changed independently")
        if task["healthCheckGracePeriodSeconds"] != state["migrationGraceSeconds"]:
            state["graceChangeAttemptedAtUtc"] = now()
            self.save(state)
            self.clients["ecs"].update_service(cluster="verify-ledger", service="verify-ledger",
                                               healthCheckGracePeriodSeconds=state["migrationGraceSeconds"])
        task = self.stable_task(state)
        require(task["healthCheckGracePeriodSeconds"] == state["migrationGraceSeconds"], "Migration health grace was not applied")
        state["phase"], state["graceVerifiedAtUtc"] = "GRACE_VERIFIED", now()
        self.save(state)
        self.target_proof()
        current, _ = self.rules(bridge, state["acmeTargetGroup"])
        forwarded, sticky = targets(current["DefaultActions"])
        wanted = {bridge: 100, SOURCE_TG: 0}
        if forwarded != wanted or sticky:
            require(forwarded == {SOURCE_TG: 1} and not sticky, "HTTPS routing changed independently")
            state["routeChangeAttemptedAtUtc"] = now()
            self.save(state)
            self.clients["elbv2"].modify_listener(ListenerArn=HTTPS, DefaultActions=[{"Type": "forward", "ForwardConfig": {
                "TargetGroups": [{"TargetGroupArn": bridge, "Weight": 100}, {"TargetGroupArn": SOURCE_TG, "Weight": 0}],
                "TargetGroupStickinessConfig": {"Enabled": False}}}])
        self.stable_task(state)
        current, _ = self.rules(bridge, state["acmeTargetGroup"])
        require(targets(current["DefaultActions"]) == (wanted, False), "SOURCE bridge HTTPS forwarding was not confirmed")
        state["phase"], state["sourceBridgeRoutedAtUtc"] = "ROUTED_SOURCE", now()
        self.save(state)
        self.target_proof()
        self.stable_task(state)
        state["deregistrationAttemptedAtUtc"] = now()
        self.save(state)
        self.clients["elbv2"].deregister_targets(TargetGroupArn=SOURCE_TG, Targets=[EXPECTED_TARGET])
        state["phase"], state["deregistrationAcknowledgedAtUtc"] = "DRAINING", now()
        self.save(state)
        self.stable_task(state)
        return {"status": "SOURCE_BRIDGE_ROUTED_DRAIN_STARTED", "state": str(STATE), "token": state["token"],
                "configuredDrainSeconds": state["before"]["sourceDeregistrationDelay"],
                "sourceTaskArn": state["before"]["task"]["taskArn"], "sourceRunningCount": 1,
                "next": "Run verify after the unchanged configured deregistration delay; SOURCE remains authoritative."}

    def verify(self, state=None):
        state = state or json.loads(STATE.read_text())
        require(state["phase"] in ("DRAINING", "DRAIN_VERIFIED"), "No initiated source deregistration to verify")
        inventory = self.inventory()
        task = self.stable_task(state)
        require(task["healthCheckGracePeriodSeconds"] == state["migrationGraceSeconds"], "Temporary source grace changed")
        elapsed_age = (datetime.now(timezone.utc) - datetime.fromisoformat(task["startedAt"])).total_seconds()
        require(state["migrationGraceSeconds"] - elapsed_age > 600, "Migration grace is nearly exhausted; recover before proceeding")
        wanted = {state["bridgeTargetGroup"]: 100, SOURCE_TG: 0}
        require(targets(inventory["httpsActions"]) == (wanted, False), "A live HTTPS route bypasses the SOURCE bridge")
        delay = state["before"]["sourceDeregistrationDelay"]
        require(inventory["sourceDeregistrationDelay"] == delay, "Original ALB drain delay changed")
        elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(state["deregistrationAcknowledgedAtUtc"])).total_seconds()
        lb = self.clients["elbv2"]
        registered = lb.describe_target_health(TargetGroupArn=SOURCE_TG)["TargetHealthDescriptions"]
        explicit = lb.describe_target_health(TargetGroupArn=SOURCE_TG, Targets=[EXPECTED_TARGET])["TargetHealthDescriptions"]
        require(len(explicit) == 1, "Explicit old-target deregistration state missing")
        old_health = explicit[0]["TargetHealth"]
        if registered or elapsed < delay or old_health.get("Reason") != "Target.NotRegistered":
            return {"status": "SOURCE_DRAIN_PENDING", "elapsedSeconds": elapsed, "configuredDelaySeconds": delay,
                    "registeredTargets": registered, "explicitTargetState": old_health,
                    "state": str(STATE), "sourceTaskUnchanged": True}
        proof = self.target_proof()
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(inventory["albDnsName"], 443, type=socket.SOCK_STREAM)})
        require(addresses and len(addresses) <= 8, "Unexpected ALB resolved addresses")
        probes = []
        for address in addresses:
            health, body = tls_request(address, "/__migration_health")
            require(health["status"] == 200 and json.loads(body) == {"service": "migration-bridge", "ok": True},
                    "A currently resolved ALB node does not reach the SOURCE bridge")
            api, body = tls_request(address, "/v1/verify-chain")
            require(api["status"] == 401 and body.startswith(b'{"error":'), "A public ALB node API behavior differs")
            probes.extend([health, api])
        self.stable_task(state)
        report = {"schemaVersion": 1, "status": "SOURCE_HTTP_DRAIN_AND_WRITER_NETWORK_VERIFIED",
                  "capturedAtUtc": now(), "token": state["token"], "accountId": ACCOUNT, "instanceId": INSTANCE,
                  "sourceHost": SOURCE_HOST, "sourcePrivateIp": SOURCE_IP, "targetPrivateIp": TARGET_IP,
                  "sourceTaskArn": task["taskArn"], "sourceImageDigest": SOURCE_IMAGE, "sourceTaskRunningCount": 1,
                  "sourceGraceExpiresAtUtc": (datetime.fromisoformat(task["startedAt"]) + timedelta(seconds=state["migrationGraceSeconds"])).isoformat(),
                  "sourceGraceRemainingSeconds": state["migrationGraceSeconds"] - elapsed_age,
                  "bridgeTargetGroup": state["bridgeTargetGroup"], "sourceTargetGroup": SOURCE_TG,
                  "drain": {"explicitDeregistrationRequested": True, "configuredDelaySeconds": delay,
                      "elapsedSeconds": elapsed, "originalDelayUnchanged": True, "targetAbsentFromRegisteredList": True,
                      "explicitTargetReason": old_health["Reason"], "explicitTargetState": old_health["State"],
                      "requestedAtUtc": state["deregistrationAttemptedAtUtc"], "acknowledgedAtUtc": state["deregistrationAcknowledgedAtUtc"]},
                  "routing": {"positiveWeightTargetGroups": [state["bridgeTargetGroup"]], "sourceTargetGroupWeight": 0,
                      "targetGroupStickinessEnabled": False, "allResolvedAlbAddressesReachBridge": True,
                      "allListenersAndRulesReviewed": True, "observedActions": inventory["httpsActions"],
                      "albProbes": probes, "targetTls": inventory["targetTls"]},
                  "writerNetwork": {"databaseClientGroups": inventory["databaseClientGroups"],
                      "allPeerInterfacesMatched": True, "noCidrOrPrefixDatabaseAccess": True,
                      "sourceDatabasePrivate": True, "sourceTaskIdentityUnchanged": True,
                      "networkInventory": inventory}, "sourceWriterProof": proof,
                  "scope": "ALB completed its unchanged configured connection drain; SOURCE application stays running. No socket-level or zero-error guarantee is claimed; final database writer fence remains required."}
        location = self.save(report, "verify-source-routing-evidence.json")
        state["phase"], state["drainVerifiedAtUtc"], state["routingEvidence"] = "DRAIN_VERIFIED", now(), location
        self.save(state)
        return {"status": report["status"], "report": str(ROOT / "verify-source-routing-evidence.json"),
                "evidenceObject": location, "sourceTaskUnchanged": True, "sourceRunningCount": 1}

    def rollback(self):
        state = json.loads(STATE.read_text())
        require(state["phase"] != "ROLLED_BACK", "Rollback already completed")
        self.stable_task(state)
        self.target_proof(invalidate=True)  # Clears the coordinator gate before public routing can change.
        require(self.group("verify-bridge-20261114", 8082)[0] == state["bridgeTargetGroup"], "Healthy bridge rollback path is missing")
        lb = self.clients["elbv2"]
        current, _ = self.rules(state["bridgeTargetGroup"], state["acmeTargetGroup"])
        forwarded, sticky = targets(current["DefaultActions"])
        require(not sticky and forwarded in ({SOURCE_TG: 1}, {state["bridgeTargetGroup"]: 100, SOURCE_TG: 0}),
                "Rollback found an unreviewed HTTPS action")
        old = lb.describe_target_health(TargetGroupArn=SOURCE_TG)["TargetHealthDescriptions"]
        require(all(item["Target"]["Id"] == SOURCE_IP and item["Target"]["Port"] == 8080 for item in old),
                "Source target group has unexpected registrations")
        if not old:
            state["rollbackRegistrationAttemptedAtUtc"] = now()
            self.save(state)
            lb.register_targets(TargetGroupArn=SOURCE_TG, Targets=[EXPECTED_TARGET])
            self.stable_task(state)
            return {"status": "ROLLBACK_WAITING_FOR_SOURCE_HEALTH", "state": str(STATE),
                    "routingRemainsSourceBridge": forwarded != {SOURCE_TG: 1}}
        if old[0]["TargetHealth"]["State"] != "healthy":
            return {"status": "ROLLBACK_WAITING_FOR_SOURCE_HEALTH", "sourceHealth": old[0]["TargetHealth"], "state": str(STATE)}
        self.target_proof(invalidate=True)
        self.stable_task(state)
        state["rollbackRouteAttemptedAtUtc"] = now()
        self.save(state)
        if forwarded != {SOURCE_TG: 1}:
            lb.modify_listener(ListenerArn=HTTPS, DefaultActions=state["before"]["httpsActions"])
        current, _ = self.rules(state["bridgeTargetGroup"], state["acmeTargetGroup"])
        require(targets(current["DefaultActions"]) == ({SOURCE_TG: 1}, False), "Old source route is not restored")
        self.stable_task(state)
        self.clients["ecs"].update_service(cluster="verify-ledger", service="verify-ledger",
            healthCheckGracePeriodSeconds=state["before"]["task"]["healthCheckGracePeriodSeconds"])
        task = self.stable_task(state)
        require(task["healthCheckGracePeriodSeconds"] == state["before"]["task"]["healthCheckGracePeriodSeconds"],
                "Original source health grace was not restored")
        state["phase"], state["rollbackCompletedAtUtc"] = "ROLLED_BACK", now()
        location = self.save(state)
        return {"status": "SOURCE_ROUTING_AND_GRACE_RESTORED", "state": str(STATE), "evidenceObject": location,
                "sourceTaskUnchanged": True, "sourceRunningCount": 1, "targetReadinessInvalidated": True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inventory", "handover", "verify", "rollback"))
    args = parser.parse_args()
    try:
        operation = Operation()
        with open(ROOT / "verify-source-route.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.operation == "inventory":
                result = {"status": "SOURCE_ROUTING_INVENTORY_VERIFIED", "inventory": operation.inventory(),
                          "targetSourceProof": operation.target_proof()}
                atomic(ROOT / "verify-source-routing-inventory.json", result)
            else:
                result = getattr(operation, args.operation)()
        print(json.dumps(result, indent=2, default=str))
        return 0
    except Exception as error:
        print(json.dumps({"status": "SOURCE_ROUTING_BLOCKED", "errorClass": type(error).__name__,
                          "reason": str(error) if isinstance(error, Blocked) else "Inspect private CloudShell/SSM evidence; no credential details emitted"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
