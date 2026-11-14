"""Offline safety and failure-boundary checks. No AWS connections are constructed."""
import copy
from datetime import datetime,timedelta,timezone
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('route',Path(__file__).with_name('route_standalone_source.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

NET={'awsvpcConfiguration':{'subnets':['subnet-00e25f0bcd6f069b9','subnet-0a4260aff60f550d8'],'securityGroups':[r.SOURCE_SG],'assignPublicIp':'DISABLED'}}
MANAGED={'taskArn':'arn:aws:ecs:us-west-2:842676017161:task/verify-ledger/managed','privateIp':'10.40.11.4','networkInterfaceId':'eni-managed','platformVersion':'1.4.0','enableExecuteCommand':False}
STANDALONE={'taskArn':'arn:aws:ecs:us-west-2:842676017161:task/verify-ledger/standalone','privateIp':'10.40.10.7','networkInterfaceId':'eni-standalone','platformVersion':'1.4.0','enableExecuteCommand':False}
BRIDGE='arn:aws:elasticloadbalancing:us-west-2:842676017161:targetgroup/verify-bridge-20261114/test'
SOURCE_ACTION=[{'Type':'forward','TargetGroupArn':r.SOURCE_TG}]

def definition():
    secret='arn:aws:secretsmanager:us-west-2:842676017161:secret:rds!db-21c38256-8c38-4e4a-a8a3-c40c8c74e117-Me0ys9'
    return {'taskDefinitionArn':r.TASK_DEFINITION,'status':'ACTIVE','networkMode':'awsvpc',
        'runtimePlatform':{'cpuArchitecture':'ARM64'},'requiresCompatibilities':['FARGATE'],
        'executionRoleArn':'arn:aws:iam::842676017161:role/verify-ledger-execution',
        'containerDefinitions':[{'name':'api','image':'842676017161.dkr.ecr.us-west-2.amazonaws.com/verify-ledger:0.4.2',
            'environment':[{'name':'VERIFY_DB_HOST','value':r.SOURCE_HOST},{'name':'VERIFY_DB_NAME','value':'verify'},{'name':'VERIFY_DB_SSLMODE','value':'require'}],
            'secrets':[{'name':'VERIFY_DB_USER','valueFrom':secret+':username::'},{'name':'VERIFY_DB_PASSWORD','valueFrom':secret+':password::'},
                       {'name':'VERIFY_EXPORT_KEY','valueFrom':'arn:aws:secretsmanager:us-west-2:842676017161:secret:verify-ledger/export-key-JkD827'}]}]}

def baseline():
    return {'service':{'networkConfiguration':copy.deepcopy(NET)},'managedTask':copy.deepcopy(MANAGED),'priorStoppedTasks':[],
        'taskDefinitionSha256':r.digest(definition()),'network':{'httpsActions':copy.deepcopy(SOURCE_ACTION),'sourceDeregistrationDelay':300,'sourceTargetGroupAttributes':{'deregistration_delay.timeout_seconds':'300','stickiness.enabled':'false'}}}

class DefinitionClient:
    def __init__(self,value):self.value=value
    def describe_task_definition(self,**kw):return {'taskDefinition':self.value}
class Ecr:
    def describe_repositories(self,**kw):return {'repositories':[{'imageTagMutability':'IMMUTABLE','imageTagMutabilityExclusionFilters':None}]}
    def describe_images(self,**kw):return {'imageDetails':[{'imageDigest':r.SOURCE_IMAGE}]}

class Flow(r.Operation):
    def __init__(self):
        self.events=[];self.action=copy.deepcopy(SOURCE_ACTION)
        self.state={'operationId':r.OPERATION,'token':'abc','accountId':r.ACCOUNT,'instanceId':r.INSTANCE,'createdAtUtc':r.now(),
                    'phase':'STANDALONE_READY','before':baseline(),'standaloneTaskArn':STANDALONE['taskArn'],
                    'standaloneStartedBy':'verify-migration-abc','oldServiceTaskArns':[MANAGED['taskArn']]}
        self.clients={'ecs':self,'elbv2':self}
        self.desired=1;self.running=1;self.old_status='STOPPED'
    def read(self):return self.state
    def refresh(self,value):return value
    def save(self,value):self.events.append('save:'+value['phase']);self.state=value
    def standalone(self,state):return STANDALONE
    def managed_one(self):return {'networkConfiguration':NET},MANAGED,[]
    def service(self):return {'desiredCount':self.desired,'runningCount':self.running,'pendingCount':0,'networkConfiguration':NET}
    def task_arns(self,service=False,desired='RUNNING'):
        if desired=='PENDING':return []
        if desired=='STOPPED':return [MANAGED['taskArn']] if self.desired==0 else []
        if service:return [MANAGED['taskArn']] if self.running else []
        return [STANDALONE['taskArn']]+([MANAGED['taskArn']] if self.running else [])
    def tasks(self,arns):return [{'taskArn':a,'lastStatus':self.old_status,'group':'service:verify-ledger','taskDefinitionArn':r.TASK_DEFINITION} for a in arns]
    def network(self,tasks):
        self.events.append('network')
        return {'httpsActions':self.action,'sourceDeregistrationDelay':300,'sourceTargetGroupAttributes':baseline()['network']['sourceTargetGroupAttributes'],
                'bridgeTargetGroup':BRIDGE,'acmeTargetGroup':'acme','publicDns':{'addresses':['1.2.3.4']}}
    def transition(self,*args):self.events.append('transition');return {'ok':True}
    def probe_alb(self,net,bridge_expected):self.events.append('probe-bridge' if bridge_expected else 'probe-source')
    def rules(self,*args):return {'DefaultActions':self.action},{}
    def modify_listener(self,**kw):self.events.append('modify-listener');self.action=kw['DefaultActions']
    def update_service(self,**kw):
        assert set(kw)=={'cluster','service','desiredCount'}
        self.events.append('desired:'+str(kw['desiredCount']));self.desired=kw['desiredCount'];return {'service':{'desiredCount':self.desired}}
    def describe_target_health(self,**kw):
        if 'Targets' in kw:return {'TargetHealthDescriptions':[{'Target':kw['Targets'][0],'TargetHealth':{'State':'unused','Reason':'Target.NotRegistered'}}]}
        return {'TargetHealthDescriptions':[]}
    def ssm(self,mode,*args):self.events.append('ssm:'+mode);return {}

class SafetyTests(unittest.TestCase):
    def test_dns_proof_checks_all_current_alb_nodes(self):
        with patch.object(r.socket,'gethostbyname_ex',side_effect=[('test.elb.amazonaws.com',[r.HOSTNAME],['1.2.3.4']),('test.elb.amazonaws.com',[],['1.2.3.4','5.6.7.8'])]):
            self.assertEqual(r.public_source_dns('test.elb.amazonaws.com')['addresses'],['1.2.3.4','5.6.7.8'])
    def test_bridge_probe_rejects_generic_200(self):
        op=object.__new__(r.Operation)
        with patch.object(r,'tls_request',return_value=({'status':200},b'{"ok":true}')):
            with self.assertRaises(r.Blocked):op.probe_alb({'publicDns':{'addresses':['1.2.3.4']}},True)
    def test_lost_rollback_scale_response_can_recover_new_managed_ip(self):
        op=Flow();op.state['phase']='ROLLBACK_SOURCE_SCALE_INTENT';op.desired=1
        def proof(mode,ip):
            self.assertEqual(mode,'rollback-proof');self.assertEqual(ip,MANAGED['privateIp'])
            return {'sourcePrivateIp':STANDALONE['privateIp'],'sourceTaskArn':STANDALONE['taskArn']}
        op.ssm=proof
        self.assertEqual(op.rollback_start()['status'],'ROLLBACK_SOURCE_STARTING')
        self.assertFalse(any(e.startswith('desired:') for e in op.events))
    def test_actual_immutable_repository_null_filters(self):
        self.assertTrue(r.tag_is_immutable({'imageTagMutability':'IMMUTABLE','imageTagMutabilityExclusionFilters':None},'0.4.2'))
    def test_mutability_exclusion_can_make_tag_unsafe(self):
        repo={'imageTagMutability':'IMMUTABLE_WITH_EXCLUSION','imageTagMutabilityExclusionFilters':[{'filterType':'WILDCARD','filter':'0.*'}]}
        self.assertFalse(r.tag_is_immutable(repo,'0.4.2'))
        self.assertFalse(r.tag_is_immutable({'imageTagMutability':'MUTABLE'},'0.4.2'))
        repo['imageTagMutability']='MUTABLE_WITH_EXCLUSION';self.assertTrue(r.tag_is_immutable(repo,'0.4.2'))
    def test_ingress_all_protocol_and_port_range_do_not_bypass(self):
        for permission in [{'IpProtocol':'-1','IpRanges':[{'CidrIp':'0.0.0.0/0'}]}, {'IpProtocol':'tcp','FromPort':1,'ToPort':65535,'Ipv6Ranges':[{'CidrIpv6':'::/0'}]}]:
            with self.assertRaises(r.Blocked):r.port_peers({'IpPermissions':[permission]},5432)
    def test_exact_role_and_secret_reference_contract(self):
        op=object.__new__(r.Operation);d=definition();op.clients={'ecs':DefinitionClient(d),'ecr':Ecr()}
        self.assertEqual(op.definition()[0],d)
        d['taskRoleArn']='arn:aws:iam::842676017161:role/unreviewed'
        with self.assertRaises(r.Blocked):op.definition()
        d.pop('taskRoleArn');d['containerDefinitions'][0]['secrets'][0]['valueFrom']='different-secret'
        with self.assertRaises(r.Blocked):op.definition()
    def test_start_records_exact_launch_before_aws_mutation(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(r,'STATE',Path(folder)/'state.json'):
            op=object.__new__(r.Operation);events=[];op.initial=lambda:baseline()
            def save(state):events.append(('save',state['phase']));r.atomic(r.STATE,state)
            def run_task(**kw):
                events.append(('run',kw));self.assertNotIn('overrides',kw);self.assertEqual(kw['networkConfiguration'],NET)
                self.assertEqual(kw['taskDefinition'],r.TASK_DEFINITION);self.assertEqual(kw['platformVersion'],'1.4.0')
                return {'tasks':[{'taskArn':STANDALONE['taskArn'],'taskDefinitionArn':r.TASK_DEFINITION,'startedBy':kw['startedBy']}]}
            op.save=save;op.clients={'ecs':SimpleNamespace(run_task=run_task)};op.start()
            self.assertEqual([e[0] for e in events],['save','run','save']);self.assertEqual(events[0][1],'RUN_TASK_INTENT')
    def test_failed_before_state_save_never_launches_task(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(r,'STATE',Path(folder)/'state.json'):
            op=object.__new__(r.Operation);op.initial=lambda:baseline();op.save=lambda _:(_ for _ in ()).throw(RuntimeError('backup failed'))
            op.clients={'ecs':SimpleNamespace(run_task=lambda **_:self.fail('must not launch'))}
            with self.assertRaises(RuntimeError):op.start()
    def test_handover_proves_bridge_before_normal_service_scale(self):
        op=Flow();answer=op.handover();self.assertEqual(answer['status'],'SOURCE_BRIDGE_NORMAL_ECS_DRAIN_STARTED')
        self.assertLess(op.events.index('save:HTTPS_ROUTE_INTENT'),op.events.index('modify-listener'))
        self.assertLess(op.events.index('probe-bridge'),op.events.index('desired:0'))
        self.assertLess(op.events.index('save:SERVICE_SCALE_ZERO_INTENT'),op.events.index('desired:0'))
        self.assertNotIn('deregister_targets',op.events)
    def test_transition_failure_cannot_route_or_scale(self):
        op=Flow();op.transition=lambda *_:(_ for _ in ()).throw(r.Blocked('not SOURCE'))
        with self.assertRaises(r.Blocked):op.handover()
        self.assertNotIn('modify-listener',op.events);self.assertNotIn('desired:0',op.events)
    def test_lost_desired_zero_response_resumes_without_rescaling(self):
        op=Flow();op.state['phase']='SERVICE_SCALE_ZERO_INTENT';op.desired=0
        answer=op.handover();self.assertEqual(answer['status'],'SERVICE_DRAINING');self.assertEqual(op.events,['save:SERVICE_DRAINING'])
    def test_running_old_request_process_blocks_drain_proof(self):
        op=Flow();op.state['phase']='SERVICE_DRAINING';op.state['scaleDownRequestedAtUtc']=(datetime.now(timezone.utc)-timedelta(seconds=400)).isoformat()
        op.desired=0;op.running=0;op.old_status='STOPPING';answer=op.verify()
        self.assertEqual(answer['status'],'PENDING_NORMAL_ECS_DRAIN');self.assertFalse(any(e.startswith('ssm:') for e in op.events))
    def test_stopped_task_does_not_skip_full_original_delay(self):
        op=Flow();op.state['phase']='SERVICE_DRAINING';op.state['scaleDownRequestedAtUtc']=r.now();op.desired=op.running=0
        self.assertEqual(op.verify()['status'],'PENDING_NORMAL_ECS_DRAIN')
    def test_rollback_invalidates_before_restoring_source_capacity(self):
        op=Flow();op.desired=op.running=0;answer=op.rollback_start()
        self.assertEqual(answer['status'],'ROLLBACK_SOURCE_STARTING')
        self.assertLess(op.events.index('ssm:standalone-invalidate'),op.events.index('desired:1'))

if __name__=='__main__':unittest.main()
