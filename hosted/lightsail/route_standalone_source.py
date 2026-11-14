#!/usr/bin/env python3
"""Guarded temporary standalone SOURCE backend and normal ECS service drain.

Run only by the parent operator in CloudShell. Start creates one temporary task
from the unchanged reviewed task definition, immutable image and source network.
After the target bridge has independently been repointed to that task, handover
routes HTTPS through the bridge and scales only the original managed service to
zero. It never manually deregisters targets, changes health grace, changes DNS,
changes a task definition, reads secrets, or changes database data/admission.

A final proof requires every prior managed task STOPPED, zero managed capacity,
unchanged full deregistration delay, explicit Target.NotRegistered, one live
standalone source task, exact SG/ENI peers and fresh target-side source authority.
Rollback restores only source capacity/routing before target activation.
"""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import fnmatch
import hashlib
import http.client
import json
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
SOURCE_HOST = "verify-ledger.cjcos4w8eowk.us-west-2.rds.amazonaws.com"
HOSTNAME = "ledger.optimise.work"
SOURCE_IMAGE = "sha256:9e67c0dd5340e4619513f539037b831406225e101ea910dcb1caaf7c7afc48b2"
TASK_DEFINITION = "arn:aws:ecs:us-west-2:842676017161:task-definition/verify-ledger:1"
CLUSTER = SERVICE = "verify-ledger"
ALB = "arn:aws:elasticloadbalancing:us-west-2:842676017161:loadbalancer/app/verify-ledger/8c146e0135e79e34"
HTTPS = "arn:aws:elasticloadbalancing:us-west-2:842676017161:listener/app/verify-ledger/8c146e0135e79e34/12730dbcac7c31ee"
SOURCE_TG = "arn:aws:elasticloadbalancing:us-west-2:842676017161:targetgroup/verify-ledger/63e16a3aeef8d276"
ALB_SG = "sg-008efd8aa7abb6352"
SOURCE_SG = "sg-0c32da8357326fd75"
DATABASE_SG = "sg-065d1882bb4a8f8a6"
TARGET_SG = "sg-0d0af838e410d73da"
BUCKET = "verify-ledger-migration-842676017161-20261114"
ROOT = Path.home() / "aws-project-migrations-20261114"
STATE = ROOT / "verify-standalone-source-state.json"
STATE_KEY = "live/verify-ledger/routing/standalone-source-20261114/current-state.json"
OPERATION = "VERIFY_STANDALONE_SOURCE_20261114"
MAX_AGE_SECONDS = 21600

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


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def tag_is_immutable(repository, tag):
    mode = repository.get("imageTagMutability")
    exclusions = (repository.get("imageTagMutabilityExclusionFilters") or [])
    require(all(e.get("filterType") == "WILDCARD" and isinstance(e.get("filter"), str) for e in exclusions),
            "Unreviewed ECR tag exclusion filter")
    excluded = any(fnmatch.fnmatchcase(tag, e["filter"]) for e in exclusions)
    if mode == "IMMUTABLE":
        require(not exclusions, "Unexpected exclusions on immutable repository")
        return True
    if mode == "IMMUTABLE_WITH_EXCLUSION":
        return not excluded
    if mode == "MUTABLE_WITH_EXCLUSION":
        return excluded
    return False


def public_source_dns(alb_dns):
    canonical, aliases, addresses = socket.gethostbyname_ex(HOSTNAME)
    _, _, expected = socket.gethostbyname_ex(alb_dns)
    require(canonical.rstrip('.').lower() == alb_dns.rstrip('.').lower()
            and addresses and set(addresses) <= set(expected) and TARGET_PUBLIC not in addresses,
            "Public DNS no longer identifies the original ALB")
    all_addresses=sorted(set(addresses)|set(expected))
    require(len(all_addresses)<=8, 'Unexpected ALB DNS address count')
    return {"canonical": canonical, "addresses": all_addresses, "publicHostnameAddresses":sorted(set(addresses)), "dnsStillOriginalAlb": True}


class Operation:
    def __init__(self):
        import boto3
        from botocore.config import Config
        cfg = Config(connect_timeout=3, read_timeout=10, retries={"max_attempts": 1})
        self.clients = {s: boto3.client(s, region_name=REGION, config=cfg) for s in
                        ("sts", "ec2", "ecs", "ecr", "rds", "elbv2", "ssm", "s3", "application-autoscaling")}
        require(self.clients['sts'].get_caller_identity()['Account'] == ACCOUNT, 'Unexpected AWS account')
        s3 = self.clients['s3']
        require((s3.get_bucket_location(Bucket=BUCKET, ExpectedBucketOwner=ACCOUNT).get('LocationConstraint') or 'us-east-1') == REGION,
                'Backup bucket region mismatch')
        require(s3.get_bucket_versioning(Bucket=BUCKET, ExpectedBucketOwner=ACCOUNT).get('Status') == 'Enabled',
                'Backup bucket must retain immutable object versions')
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(ROOT.stat().st_uid == os.getuid() and not ROOT.stat().st_mode & 0o077, 'Private evidence directory required')

    def read(self):
        value = json.loads(STATE.read_text())
        require(value.get('operationId') == OPERATION and value.get('accountId') == ACCOUNT and value.get('instanceId') == INSTANCE,
                'Wrong standalone operation state')
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(value['createdAtUtc'])).total_seconds()
        require(age >= 0, 'Standalone operation state is dated in the future')
        return value

    def save(self, value):
        value['updatedAtUtc'] = now()
        raw = encode({k:v for k,v in value.items() if not k.startswith('_s3')})
        checksum = base64.b64encode(hashlib.sha256(raw).digest()).decode()
        condition = {'IfMatch': value['_s3Etag']} if value.get('_s3Etag') else {'IfNoneMatch': '*'}
        response = self.clients['s3'].put_object(Bucket=BUCKET, Key=STATE_KEY, Body=raw,
            ExpectedBucketOwner=ACCOUNT, ServerSideEncryption='AES256', StorageClass='STANDARD',
            ChecksumSHA256=checksum, Metadata={'operation-id':OPERATION,'sha256':hashlib.sha256(raw).hexdigest()}, **condition)
        require(response.get('VersionId') not in (None,'','null'), 'Versioned before-state was not saved')
        head = self.clients['s3'].head_object(Bucket=BUCKET, Key=STATE_KEY, VersionId=response['VersionId'],
            ChecksumMode='ENABLED', ExpectedBucketOwner=ACCOUNT)
        require(head['ContentLength'] == len(raw) and head.get('ChecksumSHA256') == checksum
                and head.get('ServerSideEncryption') == 'AES256' and head.get('StorageClass','STANDARD') == 'STANDARD',
                'Before-state checksum/readability verification failed')
        value['_s3Etag'] = response['ETag']; value['_s3VersionId'] = response['VersionId']
        atomic(STATE, value)

    def refresh(self, value):
        response = self.clients['s3'].get_object(Bucket=BUCKET, Key=STATE_KEY, ExpectedBucketOwner=ACCOUNT)
        require(response['ContentLength'] <= 1024*1024, 'Unexpected operation state size')
        raw = response['Body'].read(); response['Body'].close(); remote = json.loads(raw)
        require(remote == {k:v for k,v in value.items() if not k.startswith('_s3')},
                'Remote operation state changed; use sync-state and review before retrying')
        value['_s3Etag'] = response['ETag']; value['_s3VersionId'] = response.get('VersionId')
        return value

    def sync_state(self):
        response = self.clients['s3'].get_object(Bucket=BUCKET, Key=STATE_KEY, ExpectedBucketOwner=ACCOUNT)
        require(response['ContentLength'] <= 1024*1024, 'Unexpected operation state size')
        raw = response['Body'].read(); response['Body'].close(); value=json.loads(raw)
        require(value.get('operationId')==OPERATION and value.get('accountId')==ACCOUNT and value.get('instanceId')==INSTANCE,
                'Remote state belongs to another operation')
        value['_s3Etag']=response['ETag'];value['_s3VersionId']=response.get('VersionId');atomic(STATE,value)
        return {'status':'STATE_RECOVERED_READ_ONLY','phase':value['phase'],'path':str(STATE)}

    def report(self, value, filename):
        data=encode(value); checksum=base64.b64encode(hashlib.sha256(data).digest()).decode()
        key='live/verify-ledger/routing/standalone-source-20261114/'+value['token']+'/'+filename
        response=self.clients['s3'].put_object(Bucket=BUCKET,Key=key,Body=data,ExpectedBucketOwner=ACCOUNT,
            ServerSideEncryption='AES256',StorageClass='STANDARD',ChecksumSHA256=checksum)
        require(response.get('VersionId') not in (None,'','null'),'Report version was not saved')
        head=self.clients['s3'].head_object(Bucket=BUCKET,Key=key,VersionId=response['VersionId'],ChecksumMode='ENABLED',ExpectedBucketOwner=ACCOUNT)
        require(head.get('ChecksumSHA256')==checksum and head['ContentLength']==len(data),'Report checksum mismatch')
        path=ROOT/filename;atomic(path,value)
        return {'status':value['status'],'report':str(path),'sha256':hashlib.sha256(data).hexdigest(),
                's3':{'bucket':BUCKET,'key':key,'versionId':response['VersionId']},'sourcePrivateIp':value['sourcePrivateIp']}

    def ssm(self, mode, source_ip=None):
        if mode in ('standalone-invalidate','rollback-proof'):
            operation = 'invalidate' if mode=='standalone-invalidate' else 'rollback-proof --managed-source-ip '+shlex.quote(source_ip or '')
            require(mode!='rollback-proof' or source_ip, 'Managed source IP is required for rollback proof')
            command='PYTHONPATH=/opt/verify/current/src:/opt/verify/current /opt/verify/current/.venv/bin/python -m hosted.lightsail.prepare_standalone_source '+operation
            expected='STANDALONE_SOURCE_READINESS_INVALIDATED' if mode=='standalone-invalidate' else 'STANDALONE_SOURCE_ROLLBACK_VERIFIED'
        elif mode == 'transition':
            command='PYTHONPATH=/opt/verify/current/src:/opt/verify/current /opt/verify/current/.venv/bin/python -m hosted.lightsail.prepare_standalone_source transition'
            expected='STANDALONE_SOURCE_TRANSITION_VERIFIED'
        else:
            require(mode in ('snapshot','invalidate') and source_ip,'Invalid target proof mode')
            command=('PYTHONPATH=/opt/verify/current/src:/opt/verify/current /opt/verify/current/.venv/bin/python -m hosted.lightsail.attest_source_route '+mode+' --source-private-ip '+shlex.quote(source_ip))
            expected='SOURCE_WRITER_AND_BRIDGE_VERIFIED' if mode=='snapshot' else 'SOURCE_ROUTING_READINESS_INVALIDATED'
        identifier=self.clients['ssm'].send_command(InstanceIds=[INSTANCE],DocumentName='AWS-RunShellScript',
            Parameters={'commands':[command],'executionTimeout':['40']},Comment='Verify standalone SOURCE authority proof')['Command']['CommandId']
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            try:r=self.clients['ssm'].get_command_invocation(CommandId=identifier,InstanceId=INSTANCE)
            except self.clients['ssm'].exceptions.InvocationDoesNotExist:
                time.sleep(.5);continue
            if r['Status'] in ('Pending','InProgress','Delayed'):
                time.sleep(.5);continue
            require(r['Status']=='Success' and r.get('ResponseCode')==0,'Target proof failed; inspect private SSM command '+identifier)
            proof=json.loads(r['StandardOutputContent'])
            require(proof.get('status')==expected and proof.get('accountId')==ACCOUNT and proof.get('instanceId')==INSTANCE
                    and proof.get('productionWriterEnabled') is False,'Target proof identity or writer authority differs')
            if mode not in ('invalidate','standalone-invalidate'):
                require(proof.get('sourceAdmissionAllowed') is True and proof.get('bridge',{}).get('mode')=='source'
                        and proof.get('bridge',{}).get('targetActivated') is False,'Target is not unambiguously SOURCE')
            if source_ip and mode!='rollback-proof':require(proof.get('sourcePrivateIp')==source_ip,'Target proof source IP mismatch')
            if mode=='rollback-proof':require(proof.get('managedSourcePrivateIp')==source_ip, 'Rollback managed source IP mismatch')
            proof['ssmCommandId']=identifier;return proof
        raise Blocked('Target proof pending; inspect private SSM command '+identifier)

    def service(self):
        reply=self.clients['ecs'].describe_services(cluster=CLUSTER,services=[SERVICE])
        require(not reply.get('failures') and len(reply.get('services',[]))==1,'Source service unavailable')
        s=reply['services'][0]
        require(s['status']=='ACTIVE' and s['taskDefinition']==TASK_DEFINITION and s.get('healthCheckGracePeriodSeconds',0)==0,
                'Source task definition/grace differs from restored original service')
        require(s.get('deploymentController',{}).get('type','ECS')=='ECS'
                and s['loadBalancers']==[{'targetGroupArn':SOURCE_TG,'containerName':'api','containerPort':8080}],
                'Source service controller/load-balancer identity changed')
        net=s['networkConfiguration']['awsvpcConfiguration']
        require(set(net['securityGroups'])=={SOURCE_SG} and net.get('assignPublicIp')=='DISABLED' and set(net['subnets'])=={'subnet-00e25f0bcd6f069b9','subnet-0a4260aff60f550d8'},
                'Source network does not match the reviewed private Fargate placement')
        require(not self.clients['application-autoscaling'].describe_scalable_targets(ServiceNamespace='ecs',
                ResourceIds=['service/verify-ledger/verify-ledger'])['ScalableTargets'],'Source autoscaling is present')
        return s

    def task_arns(self, service=False, desired='RUNNING'):
        args={'cluster':CLUSTER,'desiredStatus':desired}
        if service:args['serviceName']=SERVICE
        result=[]
        for page in self.clients['ecs'].get_paginator('list_tasks').paginate(**args):result.extend(page['taskArns'])
        require(len(result)<=100,'Unexpected cluster task inventory size')
        return result

    def tasks(self, arns):
        if not arns:return []
        response=self.clients['ecs'].describe_tasks(cluster=CLUSTER,tasks=list(dict.fromkeys(arns)))
        require(not response.get('failures') and len(response['tasks'])==len(set(arns)),'A recorded task is unavailable')
        return response['tasks']

    def task_info(self, task, *, started_by=None):
        require(task['lastStatus']=='RUNNING' and task['desiredStatus']=='RUNNING' and task['taskDefinitionArn']==TASK_DEFINITION
                and task.get('launchType')=='FARGATE' and task.get('startedAt') and task.get('platformVersion')
                and task.get('healthStatus')!='UNHEALTHY','Source task is not a healthy running exact revision')
        cs=task.get('containers',[])
        require(len(cs)==1 and cs[0].get('name')=='api' and cs[0].get('lastStatus')=='RUNNING'
                and cs[0].get('imageDigest')==SOURCE_IMAGE,'Source image digest differs')
        require(not task.get('overrides',{}).get('taskRoleArn') and not task.get('overrides',{}).get('executionRoleArn')
                and all(not set(o)-{'name'} for o in task.get('overrides',{}).get('containerOverrides',[])),
                'Unexpected source task role/container override')
        if started_by:require(task.get('startedBy')==started_by and task.get('group')=='family:verify-ledger','Task is not the exact standalone operation')
        else:require(task.get('group')=='service:verify-ledger','Task is not part of the original service')
        at=[a for a in task.get('attachments',[]) if a['type']=='ElasticNetworkInterface']
        require(len(at)==1 and at[0].get('status')=='ATTACHED','Source network attachment unavailable')
        details={d['name']:d['value'] for d in at[0]['details']}
        require(details.get('privateIPv4Address') and details.get('networkInterfaceId'),'Task private network identity missing')
        return {'taskArn':task['taskArn'],'privateIp':details['privateIPv4Address'],'networkInterfaceId':details['networkInterfaceId'],
                'subnetId':details.get('subnetId'),'imageDigest':SOURCE_IMAGE,'taskDefinitionArn':TASK_DEFINITION,
                'group':task.get('group'),'startedBy':task.get('startedBy'),'startedAt':str(task['startedAt']),
                'platformVersion':task['platformVersion'],'enableExecuteCommand':task.get('enableExecuteCommand',False)}

    def definition(self):
        d=self.clients['ecs'].describe_task_definition(taskDefinition=TASK_DEFINITION)['taskDefinition']
        require(d['taskDefinitionArn']==TASK_DEFINITION and d['status']=='ACTIVE' and d['networkMode']=='awsvpc'
                and d.get('runtimePlatform',{}).get('cpuArchitecture')=='ARM64' and 'FARGATE' in d.get('requiresCompatibilities',[]) 
                and len(d['containerDefinitions'])==1,'Original task definition identity changed')
        c=d['containerDefinitions'][0];env={e['name']:e['value'] for e in c.get('environment',[])}
        require(c['name']=='api' and set(env)=={'VERIFY_DB_HOST','VERIFY_DB_NAME','VERIFY_DB_SSLMODE'}
                and env['VERIFY_DB_HOST']==SOURCE_HOST and env['VERIFY_DB_NAME']=='verify'
                and env['VERIFY_DB_SSLMODE'] in ('require','verify-ca','verify-full'), 'Task database configuration differs')
        require(not d.get('taskRoleArn') and d.get('executionRoleArn')=='arn:aws:iam::842676017161:role/verify-ledger-execution',
                'Source task must retain absent application role and exact execution role')
        secret='arn:aws:secretsmanager:us-west-2:842676017161:secret:rds!db-21c38256-8c38-4e4a-a8a3-c40c8c74e117-Me0ys9'
        expected_secrets={'VERIFY_DB_USER':secret+':username::','VERIFY_DB_PASSWORD':secret+':password::',
            'VERIFY_EXPORT_KEY':'arn:aws:secretsmanager:us-west-2:842676017161:secret:verify-ledger/export-key-JkD827'}
        require(len(c.get('secrets',[]))==3 and {v['name']:v['valueFrom'] for v in c['secrets']}==expected_secrets,
                'Original database/export secret references changed')
        image=c['image'];require(image=='842676017161.dkr.ecr.us-west-2.amazonaws.com/verify-ledger:0.4.2', 'Source image URI changed')
        prefix=ACCOUNT+'.dkr.ecr.'+REGION+'.amazonaws.com/'
        require(image.startswith(prefix),'Image does not belong to the expected private ECR registry')
        image_path=image[len(prefix):]
        if '@sha256:' in image_path:
            repository,sha=image_path.split('@',1);require(sha==SOURCE_IMAGE,'Pinned task image digest differs');image_id={'imageDigest':sha};tag=None
        else:
            require(':' in image_path,'Task image must explicitly name a tag or digest')
            repository,tag=image_path.rsplit(':',1);image_id={'imageTag':tag}
        repos=self.clients['ecr'].describe_repositories(repositoryNames=[repository])['repositories'];require(len(repos)==1,'Image repository missing')
        if tag:require(tag_is_immutable(repos[0],tag),'Existing task image tag is mutable; do not start a new backend from it')
        images=self.clients['ecr'].describe_images(repositoryName=repository,imageIds=[image_id])['imageDetails']
        require(len(images)==1 and images[0]['imageDigest']==SOURCE_IMAGE,'Current ECR image does not match the serving digest')
        return d,{'imageUri':image,'repository':repository,'tag':tag,'imageDigest':SOURCE_IMAGE,
                  'tagMutability':repos[0].get('imageTagMutability'),'tagImmutableOrDigestPinned':True}

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

    def network(self, task_infos):
        ec,lb=self.clients['ec2'],self.clients['elbv2']
        dbs=self.clients['rds'].describe_db_instances(DBInstanceIdentifier='verify-ledger')['DBInstances']
        require(len(dbs)==1,'Source database missing');db=dbs[0]
        require(db['DBInstanceStatus']=='available' and db['Engine']=='postgres' and db['EngineVersion'].startswith('16.')
                and db.get('DBName')=='verify' and db.get('MasterUsername')=='verify_owner'
                and db['Endpoint']['Address']==SOURCE_HOST and db['Endpoint']['Port']==5432
                and not db.get('PubliclyAccessible') and db['DBSubnetGroup']['VpcId']==VPC
                and {g['VpcSecurityGroupId'] for g in db['VpcSecurityGroups']}=={DATABASE_SG}
                and db.get('BackupRetentionPeriod')==7,'Source database identity/privacy/retention differs')
        reservations=ec.describe_instances(InstanceIds=[INSTANCE])['Reservations']
        require(len(reservations)==1 and len(reservations[0]['Instances'])==1,'Target instance missing');instance=reservations[0]['Instances'][0]
        require(instance['State']['Name']=='running' and instance['VpcId']==VPC and instance['PrivateIpAddress']==TARGET_IP
                and instance.get('PublicIpAddress')==TARGET_PUBLIC and {g['GroupId'] for g in instance['SecurityGroups']}=={TARGET_SG},
                'Target instance placement differs')
        groups={g['GroupId']:g for g in ec.describe_security_groups(GroupIds=[DATABASE_SG,SOURCE_SG,TARGET_SG,ALB_SG])['SecurityGroups']}
        require(set(groups)=={DATABASE_SG,SOURCE_SG,TARGET_SG,ALB_SG} and all(g['VpcId']==VPC for g in groups.values()),'Security-group identities differ')
        db_peers,db_rules=port_peers(groups[DATABASE_SG],5432);app_peers,app_rules=port_peers(groups[SOURCE_SG],8080)
        require(db_peers=={SOURCE_SG,TARGET_SG} and app_peers=={ALB_SG,TARGET_SG},'Additional database/application network writers exist')
        interfaces=[]
        for page in ec.get_paginator('describe_network_interfaces').paginate(Filters=[{'Name':'group-id','Values':[SOURCE_SG,TARGET_SG,ALB_SG]}]):
            interfaces.extend(page['NetworkInterfaces'])
        by_group={g:[e for e in interfaces if g in {a['GroupId'] for a in e['Groups']}] for g in (SOURCE_SG,TARGET_SG,ALB_SG)}
        require({e['NetworkInterfaceId'] for e in by_group[SOURCE_SG]}=={t['networkInterfaceId'] for t in task_infos},
                'Source SG contains an unreviewed or lingering network interface')
        task_by_eni={t['networkInterfaceId']:t for t in task_infos}
        for e in by_group[SOURCE_SG]:
            require(e['Status']=='in-use' and not e.get('Association') and {g['GroupId'] for g in e['Groups']}=={SOURCE_SG}
                    and e['PrivateIpAddress']==task_by_eni[e['NetworkInterfaceId']]['privateIp'] and e['VpcId']==VPC,
                    'Source task interface has unexpected public access, groups or address')
        target_enis={e['NetworkInterfaceId'] for e in instance['NetworkInterfaces']}
        require(len(target_enis)==1 and {e['NetworkInterfaceId'] for e in by_group[TARGET_SG]}==target_enis,
                'Target writer security group has another client')
        description='ELB '+ALB.split('loadbalancer/',1)[1]
        require(by_group[ALB_SG] and all(e.get('Description')==description and e['Status']=='in-use' for e in by_group[ALB_SG]),
                'ALB client group is attached elsewhere')
        bridge,bridge_health=self.group('verify-bridge-20261114',8082)
        acme,acme_health=self.group('verify-acme-20261114',80)
        listener,rules=self.rules(bridge,acme)
        load=lb.describe_load_balancers(LoadBalancerArns=[ALB])['LoadBalancers'][0]
        require(load['VpcId']==VPC and set(load['SecurityGroups'])=={ALB_SG},'ALB placement changed')
        source=lb.describe_target_groups(TargetGroupArns=[SOURCE_TG])['TargetGroups'][0]
        require(source['VpcId']==VPC and source['TargetType']=='ip' and source['Port']==8080 and source['Protocol']=='HTTP','Source target group changed')
        attrs={a['Key']:a['Value'] for a in lb.describe_target_group_attributes(TargetGroupArn=SOURCE_TG)['Attributes']}
        require(attrs.get('stickiness.enabled')=='false','Source target-group stickiness is enabled')
        delay=int(attrs['deregistration_delay.timeout_seconds']);require(0<=delay<=3600,'Unexpected deregistration delay')
        dns=public_source_dns(load['DNSName'])
        return {'capturedAtUtc':now(),'sourceDatabase':{'endpoint':SOURCE_HOST,'version':db['EngineVersion'],'backupRetentionDays':7,
                    'private':True,'vpcId':VPC,'securityGroup':DATABASE_SG},
                'writerNetwork':{'databaseClientGroups':sorted(db_peers),'appClientGroups':sorted(app_peers),
                    'databaseIngressRules':db_rules,'appIngressRules':app_rules,'allPeerInterfacesMatched':True,
                    'noCidrOrPrefixDatabaseAccess':True,'sourceDatabasePrivate':True,'sourceTaskIdentityUnchanged':True,
                    'peerInterfaces':{g:[{'id':e['NetworkInterfaceId'],'privateIp':e['PrivateIpAddress'],'status':e['Status']} for e in es] for g,es in by_group.items()}},
                'bridgeTargetGroup':bridge,'acmeTargetGroup':acme,'bridgeHealth':bridge_health,'acmeHealth':acme_health,
                'httpsActions':listener['DefaultActions'],'rules':rules,'sourceDeregistrationDelay':delay,
                'sourceTargetGroupAttributes':attrs,'albDnsName':load['DNSName'],'publicDns':dns}

    def managed_one(self):
        service=self.service()
        require(service['desiredCount']==service['runningCount']==1 and service['pendingCount']==0,'Source service must have one running task')
        deployments=service['deployments']
        require(len(deployments)==1 and deployments[0]['status']=='PRIMARY' and deployments[0].get('rolloutState')=='COMPLETED','Source deployment is changing')
        arns=self.task_arns(service=True)
        require(len(arns)==1 and not self.task_arns(service=True,desired='PENDING'),'Source has extra running/pending tasks')
        info=self.task_info(self.tasks(arns)[0]);net=service['networkConfiguration']['awsvpcConfiguration']
        require(info['subnetId'] in net['subnets'],'Managed source task subnet differs')
        recent=self.tasks(self.task_arns(service=True,desired='STOPPED'))
        require(all(t['lastStatus']=='STOPPED' for t in recent),'An older managed task is still stopping')
        targets_now=self.clients['elbv2'].describe_target_health(TargetGroupArn=SOURCE_TG)['TargetHealthDescriptions']
        require(len(targets_now)==1 and targets_now[0]['Target']['Id']==info['privateIp'] and targets_now[0]['Target']['Port']==8080
                and targets_now[0]['TargetHealth']['State']=='healthy','The original managed source is not uniquely healthy behind its ALB')
        return service,info,recent

    def initial(self):
        service,task,recent=self.managed_one()
        require(set(self.task_arns())=={task['taskArn']} and not self.task_arns(desired='PENDING'),'Cluster has an unexpected non-service task')
        definition,image=self.definition();network=self.network([task])
        require(targets(network['httpsActions'])==({SOURCE_TG:1},False),'Original HTTPS route must be exclusively source before standalone start')
        proof=self.ssm('snapshot',task['privateIp'])
        self.probe_alb(network,bridge_expected=False)
        return {'capturedAtUtc':now(),'service':service,'managedTask':task,'priorStoppedTasks':[{'taskArn':t['taskArn'],'lastStatus':t['lastStatus']} for t in recent],
                'taskDefinition':definition,'taskDefinitionSha256':digest(definition),'image':image,'network':network,'targetSourceProof':proof}

    def start(self):
        if STATE.exists():
            state=self.refresh(self.read())
            age=(datetime.now(timezone.utc)-datetime.fromisoformat(state['createdAtUtc'])).total_seconds()
            require(age<=MAX_AGE_SECONDS, 'Review an ambiguous RunTask response older than six hours before retrying')
            require(state['phase']=='RUN_TASK_INTENT','A standalone operation exists; use ready/status/recovery instead of starting again')
            # Same client token and full request preserve idempotency after an ambiguous response.
            service,task,_=self.managed_one();require(task['taskArn']==state['before']['managedTask']['taskArn'],'Managed task changed before launch retry')
            require(digest(self.definition()[0])==state['before']['taskDefinitionSha256'],'Task definition differs from saved before-state')
        else:
            before=self.initial();token=uuid.uuid4().hex[:12]
            state={'schemaVersion':1,'operationId':OPERATION,'token':token,'accountId':ACCOUNT,'instanceId':INSTANCE,'createdAtUtc':now(),
                   'phase':'RUN_TASK_INTENT','before':before,'standaloneStartedBy':'verify-migration-'+token,
                   'oldServiceTaskArns':[before['managedTask']['taskArn']]+[t['taskArn'] for t in before['priorStoppedTasks']]}
            state['runTaskRequest']={'cluster':CLUSTER,'taskDefinition':TASK_DEFINITION,'count':1,'launchType':'FARGATE',
                'platformVersion':before['managedTask']['platformVersion'],'networkConfiguration':before['service']['networkConfiguration'],
                'enableExecuteCommand':before['managedTask']['enableExecuteCommand'],'startedBy':state['standaloneStartedBy'],
                'clientToken':token,'tags':[{'key':'project','value':'verify-ledger'},{'key':'MigrationOperation','value':token}]}
            self.save(state)
        response=self.clients['ecs'].run_task(**state['runTaskRequest'])
        require(not response.get('failures') and len(response.get('tasks',[]))==1,'Standalone task start failed; inspect saved idempotent launch state')
        task=response['tasks'][0]
        require(task.get('taskDefinitionArn')==TASK_DEFINITION and task.get('startedBy')==state['standaloneStartedBy'],
                'Started task identity differs from exact launch request')
        state['standaloneTaskArn']=task['taskArn'];state['phase']='STANDALONE_START_REQUESTED';self.save(state)
        return {'status':'STANDALONE_START_REQUESTED','taskArn':task['taskArn'],'state':str(STATE),'sourceRoutingChanged':False,
                'sourceServiceChanged':False,'next':'Run ready after the standalone task reaches RUNNING; then use the target prepare adapter with its pinned report'}

    def standalone(self,state):
        info=self.task_info(self.tasks([state['standaloneTaskArn']])[0],started_by=state['standaloneStartedBy'])
        require(info['subnetId'] in state['before']['service']['networkConfiguration']['awsvpcConfiguration']['subnets'],
                'Standalone task is outside original source subnets')
        require(info['platformVersion']==state['before']['managedTask']['platformVersion'],'Standalone platform version differs')
        require(digest(self.definition()[0])==state['before']['taskDefinitionSha256'],'Original task definition/configuration changed')
        groups=[]
        for page in self.clients['elbv2'].get_paginator('describe_target_groups').paginate():
            for group in page['TargetGroups']:
                if group['VpcId']!=VPC:continue
                rows=self.clients['elbv2'].describe_target_health(TargetGroupArn=group['TargetGroupArn'])['TargetHealthDescriptions']
                if any(r['Target']['Id']==info['privateIp'] for r in rows):groups.append(group['TargetGroupArn'])
        require(not groups,'Standalone source is unexpectedly registered with an ALB target group')
        return info

    def ready(self):
        state=self.refresh(self.read());require(state['phase'] in ('STANDALONE_START_REQUESTED','STANDALONE_READY'),'Wrong readiness phase')
        service,managed,recent=self.managed_one();standalone=self.standalone(state)
        require(managed['taskArn']==state['before']['managedTask']['taskArn'],'Managed source changed before bridge preparation')
        require(service['networkConfiguration']==state['before']['service']['networkConfiguration'],'Source service network changed')
        require(set(self.task_arns())=={managed['taskArn'],standalone['taskArn']} and not self.task_arns(desired='PENDING'),
                'Unexpected source cluster task')
        net=self.network([managed,standalone]);require(targets(net['httpsActions'])==({SOURCE_TG:1},False),'Original source HTTPS route changed')
        self.probe_alb(net,bridge_expected=False)
        # Readiness establishes AWS identity; target prepare independently probes
        # API/source TLS and writer authority before touching the unused bridge.
        state['standalone']=standalone;state['phase']='STANDALONE_READY';self.save(state)
        report={'status':'STANDALONE_SOURCE_TASK_READY','capturedAtUtc':now(),'token':state['token'],'accountId':ACCOUNT,'instanceId':INSTANCE,
            'region':REGION,'sourceHost':SOURCE_HOST,'targetPrivateIp':TARGET_IP,'sourcePrivateIp':standalone['privateIp'],
            'sourceTaskArn':standalone['taskArn'],'sourceTaskDefinition':TASK_DEFINITION,'sourceImageDigest':SOURCE_IMAGE,
            'sourceEni':standalone['networkInterfaceId'],'sourceStartedAtUtc':standalone['startedAt'],'sourceBackendKind':'standalone',
            'standaloneStartedBy':state['standaloneStartedBy'],'sourceTaskGroup':'family:verify-ledger','standaloneRegisteredTargetGroups':[],
            'originalServiceTaskIps':[managed['privateIp']],'originalServiceTaskArns':[managed['taskArn']],
            'originalServiceDesiredCount':1,'originalServiceHealthy':True,'originalServiceGraceSeconds':0,
            'sourceTargetGroup':SOURCE_TG,'bridgeTargetGroup':net['bridgeTargetGroup'],'httpsSourceOnly':True,'dnsStillOriginalAlb':True,
            'originalSourceTargetsHealthy':True,'writerNetwork':net['writerNetwork'],'imageProof':state['before']['image'],
            'stateVersionId':state['_s3VersionId'],'sourceRoutingChanged':False,'sourceServiceChanged':False}
        return self.report(report,'verify-standalone-source-ready.json')

    def probe_alb(self,network,bridge_expected):
        addresses=network['publicDns']['addresses'];responses=[]
        for address in addresses:
            health,body=tls_request(address,'/__migration_health')
            if bridge_expected:
                require(health['status']==200 and json.loads(body)=={'service':'migration-bridge','ok':True},
                        'An ALB node does not reach the exact migration bridge health endpoint')
            else:require(health['status']==404,'Original source ALB unexpectedly reaches the migration bridge')
            api,body=tls_request(address,'/v1/verify-chain');require(api['status']==401 and body.startswith(b'{"error":'),'Source API TLS probe failed')
            responses.append({'health':health,'api':api})
        return responses

    def transition(self,state,standalone):
        proof=self.ssm('transition')
        require(proof.get('sourcePrivateIp')==standalone['privateIp'] and proof.get('sourceTaskArn')==standalone['taskArn']
                and proof.get('standaloneStartedBy')==state['standaloneStartedBy']
                and set(proof.get('permittedManagedSourceIps',[]))=={state['before']['managedTask']['privateIp']},
                'Bridge transition proof does not match this exact standalone/managed source pair')
        return proof

    def handover(self):
        state=self.refresh(self.read());require(state['phase'] in ('STANDALONE_READY','HTTPS_ROUTE_INTENT','HTTPS_BRIDGE_CONFIRMED','SERVICE_SCALE_ZERO_INTENT','SERVICE_DRAINING'),
                'Wrong handover phase')
        if state['phase']=='SERVICE_DRAINING':return {'status':'SERVICE_DRAINING','state':str(STATE),'next':'verify after unchanged deregistration delay'}
        if state['phase']=='SERVICE_SCALE_ZERO_INTENT' and self.service()['desiredCount']==0:
            # update_service may have succeeded even if its response was lost.
            state['phase']='SERVICE_DRAINING';self.save(state)
            return {'status':'SERVICE_DRAINING','state':str(STATE),'next':'verify; recovered an already applied desiredCount zero'}
        standalone=self.standalone(state);service,managed,recent=self.managed_one()
        require(managed['taskArn']==state['before']['managedTask']['taskArn'] and service['networkConfiguration']==state['before']['service']['networkConfiguration'],
                'Managed source identity/network changed before normal scale-down')
        require(set(self.task_arns())=={managed['taskArn'],standalone['taskArn']},'Unexpected cluster task before handover')
        net=self.network([managed,standalone]);require(net['sourceTargetGroupAttributes']==state['before']['network']['sourceTargetGroupAttributes'],
                'Original source target attributes changed')
        proof=self.transition(state,standalone);bridge=net['bridgeTargetGroup'];wanted=({bridge:100,SOURCE_TG:0},False)
        current=targets(net['httpsActions'])
        require(current in [({SOURCE_TG:1},False),wanted],'Unreviewed HTTPS forwarding action')
        if current!=wanted:
            state['phase']='HTTPS_ROUTE_INTENT';self.save(state)
            self.clients['elbv2'].modify_listener(ListenerArn=HTTPS,DefaultActions=[{'Type':'forward','ForwardConfig':{
                'TargetGroups':[{'TargetGroupArn':bridge,'Weight':100},{'TargetGroupArn':SOURCE_TG,'Weight':0}],
                'TargetGroupStickinessConfig':{'Enabled':False}}}])
        listener,rules=self.rules(bridge,net['acmeTargetGroup']);require(targets(listener['DefaultActions'])==wanted,'HTTPS bridge route not confirmed')
        self.probe_alb(net,bridge_expected=True)
        proof=self.transition(state,standalone)
        state['phase']='HTTPS_BRIDGE_CONFIRMED';state['bridgeTargetGroup']=bridge;state['targetTransitionProof']=proof;self.save(state)
        # Capture every managed task seen before shutdown. Do not stop a stale IP
        # manually; ECS owns graceful deregistration and process termination.
        current_service,current_managed,recent=self.managed_one()
        require(current_managed['taskArn']==managed['taskArn'],'Managed task changed at shutdown boundary')
        state['oldServiceTaskArns']=sorted(set(state['oldServiceTaskArns']+[current_managed['taskArn']]+[t['taskArn'] for t in recent]))
        state['phase']='SERVICE_SCALE_ZERO_INTENT';state['scaleDownRequestedAtUtc']=now();self.save(state)
        response=self.clients['ecs'].update_service(cluster=CLUSTER,service=SERVICE,desiredCount=0)
        require(response['service']['desiredCount']==0,'Managed source desired zero not confirmed')
        state['phase']='SERVICE_DRAINING';self.save(state)
        return {'status':'SOURCE_BRIDGE_NORMAL_ECS_DRAIN_STARTED','state':str(STATE),'token':state['token'],
                'configuredDelaySeconds':net['sourceDeregistrationDelay'],'standaloneTaskArn':standalone['taskArn'],
                'sourceDatabaseStillAuthoritative':True,'manualDeregistration':False,'healthGraceChanged':False}

    def verify(self):
        state=self.refresh(self.read());require(state['phase'] in ('SERVICE_DRAINING','SERVICE_SCALE_ZERO_INTENT','DRAIN_VERIFIED'),'Wrong drain verification phase')
        service=self.service();standalone=self.standalone(state)
        require(service['desiredCount']==0,'Original managed service was scaled up independently')
        old_tasks=self.tasks(sorted(set(state['oldServiceTaskArns']+self.task_arns(service=True,desired='STOPPED')+self.task_arns(service=True))))
        elapsed=(datetime.now(timezone.utc)-datetime.fromisoformat(state['scaleDownRequestedAtUtc'])).total_seconds()
        delay=state['before']['network']['sourceDeregistrationDelay']
        if service['runningCount'] or service['pendingCount'] or any(t['lastStatus']!='STOPPED' for t in old_tasks) or elapsed<delay:
            return {'status':'PENDING_NORMAL_ECS_DRAIN','elapsedSeconds':elapsed,'configuredDelaySeconds':delay,
                    'managedRunning':service['runningCount'],'managedPending':service['pendingCount'],
                    'oldTasks':[{'taskArn':t['taskArn'],'lastStatus':t['lastStatus']} for t in old_tasks]}
        require(old_tasks and all(t.get('group')=='service:verify-ledger' and t['taskDefinitionArn']==TASK_DEFINITION for t in old_tasks),
                'Recorded old service task identity differs')
        require(not self.task_arns(service=True) and not self.task_arns(service=True,desired='PENDING')
                and set(self.task_arns())=={standalone['taskArn']} and not self.task_arns(desired='PENDING'),'Unexpected remaining source task')
        registered=self.clients['elbv2'].describe_target_health(TargetGroupArn=SOURCE_TG)['TargetHealthDescriptions']
        expected={'Id':state['before']['managedTask']['privateIp'],'Port':8080}
        explicit=self.clients['elbv2'].describe_target_health(TargetGroupArn=SOURCE_TG,Targets=[expected])['TargetHealthDescriptions']
        require(not registered and len(explicit)==1 and explicit[0]['TargetHealth'].get('Reason')=='Target.NotRegistered',
                'Old managed source target deregistration is incomplete')
        net=self.network([standalone]);require(net['sourceTargetGroupAttributes']==state['before']['network']['sourceTargetGroupAttributes'],
                'Original deregistration delay/target attributes changed')
        require(targets(net['httpsActions'])==({net['bridgeTargetGroup']:100,SOURCE_TG:0},False),'Public HTTPS can bypass the standalone SOURCE bridge')
        self.probe_alb(net,bridge_expected=True);proof=self.ssm('snapshot',standalone['privateIp'])
        state['phase']='DRAIN_VERIFIED';state['standalone']=standalone;self.save(state)
        report={'status':'SOURCE_HTTP_DRAIN_AND_WRITER_NETWORK_VERIFIED','capturedAtUtc':now(),'token':state['token'],
                'accountId':ACCOUNT,'instanceId':INSTANCE,'region':REGION,'sourceHost':SOURCE_HOST,'targetPrivateIp':TARGET_IP,
                'sourcePrivateIp':standalone['privateIp'],'sourceTaskArn':standalone['taskArn'],'sourceImageDigest':SOURCE_IMAGE,
                'sourceTaskDefinition':TASK_DEFINITION,'sourceTaskRunningCount':1,'sourceBackendKind':'standalone',
                'standaloneStartedBy':state['standaloneStartedBy'],'sourceTaskGroup':'family:verify-ledger','singleStandaloneRunning':True,
                'drainMethod':'ECS_SERVICE_STOPPED_STANDALONE_SOURCE','originalServiceDesiredCount':0,
                'originalServiceRunningCount':0,'originalServicePendingCount':0,'standaloneRegisteredTargetGroups':[],
                'oldServiceTasks':[{'taskArn':t['taskArn'],'lastStatus':t['lastStatus']} for t in old_tasks],
                'drain':{'serviceScaleDownRequested':True,'configuredDelaySeconds':delay,'elapsedSeconds':elapsed,
                    'originalDelayUnchanged':True,'targetAbsentFromRegisteredList':True,'allOldTargetsNotRegistered':True,
                    'explicitTargetReason':'Target.NotRegistered','explicitDeregistrationRequested':False},
                'routing':{'positiveWeightTargetGroups':[net['bridgeTargetGroup']],'sourceTargetGroupWeight':0,
                    'targetGroupStickinessEnabled':False,'allResolvedAlbAddressesReachBridge':True,'allListenersAndRulesReviewed':True},
                'writerNetwork':net['writerNetwork'],'bridgeTargetGroup':net['bridgeTargetGroup'],'sourceTargetGroup':SOURCE_TG,
                'targetSourceProof':proof,'dnsStillOriginalAlb':True,'stateVersionId':state['_s3VersionId'],
                'healthGraceChanged':False,'scope':'Every prior managed process is stopped; only the standalone source backend can receive gated requests. Final database SHARE/admission fence remains mandatory.'}
        return self.report(report,'verify-standalone-source-drain.json')

    def rollback_start(self):
        state=self.refresh(self.read());standalone=self.standalone(state)
        service=self.service()
        if state['phase'] in ('ROLLBACK_SOURCE_SCALE_INTENT','ROLLBACK_SOURCE_STARTING') and service['desiredCount']==1:
            # An earlier update may have applied despite a lost response. The
            # pre-update state proves readiness was invalidated; fresh proof on
            # the actual replacement task is still mandatory before routing.
            _,managed,_=self.managed_one()
            proof=self.ssm('rollback-proof',managed['privateIp'])
            require(proof.get('sourcePrivateIp')==standalone['privateIp'] and proof.get('sourceTaskArn')==standalone['taskArn'],
                    'Rollback recovery standalone identity differs')
            state['phase']='ROLLBACK_SOURCE_STARTING';self.save(state)
            return {'status':'ROLLBACK_SOURCE_STARTING','sourceTaskArn':managed['taskArn'],'next':'rollback-finish; recovered applied desiredCount one'}
        # Source admission and durable SOURCE/no-writer must be proven before any
        # source service resurrection. A failed/uncertain proof blocks rollback.
        self.ssm('standalone-invalidate')
        service=self.service();require(service['desiredCount'] in (0,1),'Unexpected managed capacity')
        require(service['networkConfiguration']==state['before']['service']['networkConfiguration'],'Source network changed')
        if service['desiredCount']==0:
            state['phase']='ROLLBACK_SOURCE_SCALE_INTENT';self.save(state)
            self.clients['ecs'].update_service(cluster=CLUSTER,service=SERVICE,desiredCount=1)
        state['phase']='ROLLBACK_SOURCE_STARTING';self.save(state)
        return {'status':'ROLLBACK_SOURCE_STARTING','publicRoutingStillBridge':True,'next':'Wait for the current ECS-managed task and source target healthy, then rollback-finish. Never re-register the old IP.'}

    def rollback_finish(self):
        state=self.refresh(self.read());require(state['phase'] in ('ROLLBACK_SOURCE_SCALE_INTENT','ROLLBACK_SOURCE_STARTING','ROLLBACK_ROUTE_INTENT','ROLLED_BACK'),'Wrong rollback phase')
        standalone=self.standalone(state);service,managed,recent=self.managed_one()
        proof=self.ssm('rollback-proof',managed['privateIp'])
        require(proof.get('sourcePrivateIp')==standalone['privateIp'] and proof.get('sourceTaskArn')==standalone['taskArn']
                and proof.get('standaloneStartedBy')==state['standaloneStartedBy'], 'Rollback proof standalone identity differs')
        net=self.network([managed,standalone]);current=targets(net['httpsActions'])
        require(current in [({SOURCE_TG:1},False),({net['bridgeTargetGroup']:100,SOURCE_TG:0},False)],'Unreviewed routing during rollback')
        state['phase']='ROLLBACK_ROUTE_INTENT';self.save(state)
        self.clients['elbv2'].modify_listener(ListenerArn=HTTPS,DefaultActions=state['before']['network']['httpsActions'])
        listener,_=self.rules(net['bridgeTargetGroup'],net['acmeTargetGroup']);require(targets(listener['DefaultActions'])==({SOURCE_TG:1},False),'Original source route not restored')
        self.probe_alb(net,bridge_expected=False)
        state['phase']='ROLLED_BACK';self.save(state)
        return {'status':'SOURCE_PUBLIC_ROUTE_RESTORED','temporaryTaskRetainedForExplicitReviewedCleanup':standalone['taskArn']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['inventory','start','ready','handover','verify','sync-state','rollback-start','rollback-finish'])
    args=parser.parse_args();os.umask(0o077)
    try:
        ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
        with open(ROOT/'verify-standalone-source.lock','w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);op=Operation()
            if args.operation=='inventory':
                value=op.initial();path=ROOT/'verify-standalone-source-inventory.json';atomic(path,value)
                result={'status':'READ_ONLY_SOURCE_INVENTORY_VERIFIED','path':str(path),'sourceTaskArn':value['managedTask']['taskArn'],
                        'sourcePrivateIp':value['managedTask']['privateIp'],'immutableImage':value['image'],'sourceDatabaseChanges':0}
            else:result=getattr(op,args.operation.replace('-','_'))()
        print(json.dumps(result,default=str));return 0
    except Exception as error:
        print(json.dumps({'status':'STANDALONE_SOURCE_OPERATION_BLOCKED','errorClass':type(error).__name__,
            'reason':str(error) if isinstance(error,Blocked) else 'Inspect private operation evidence; credentials and AWS response payloads suppressed'}))
        return 2


if __name__=='__main__':
    raise SystemExit(main())
