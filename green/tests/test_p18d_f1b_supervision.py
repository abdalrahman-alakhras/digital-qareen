"""F1B-L2/L3: cancellation and entrypoint supervision review, no Git writes.
Selected committed definitions; actual asyncio tasks, synthetic IO and signals.
"""
import ast, asyncio, builtins, copy, difflib, hashlib, json, os, signal, subprocess, sys, types, unittest
from pathlib import Path

W='app/outbox_worker.py'; E='app/run_worker.py'; I='app/postgres_identity.py'; G='app/auth/provider_dispatch_gate.py'
L='tests/test_p18d_f1b_lifecycle.py'; N='tests/test_p18d_f1b_supervision.py'
T='tests/test_p18d_c2_permanent_db_authority_denial.py'; C='tests/test_p18d_c2e_propagation.py'
S='tests/test_p18d_c2e_startup_contract.py'; B='tests/test_p18d_c2e_strict_barrier_propagation.py'
HEAD='9c75c9f7b343c692ca7b50d479e61063a95f81b8'; BASE='feb748cea75470240c54358f591fcb37676aef4c'
RED='e8a31eea265591c6988aba6f802deec2888ceb34'; TIP='7db98b060e7ec77a3139de7a839c0799f85d627a'
ACTIVE='refs/heads/fix/phase16-canonical-postgres'; REF='refs/heads/evidence/p18d-f1a-propagation'
MANIFEST='415EB12F7451A0A826C41638EEAEE0BD9A08A30EFE3941608F8851215AB76B5A'
PINS={W:'6C8F03FF475DAC725B13CA6672E577E46FE82BF063E8E8B767720032D3F7B843', E:'2E453E3F31155AE074AB3426FD25E0826323829533F7948F1F3D53D6808BBA8C', I:'1D7CAB504A20C0A7A864948491C6FB107BF0F610036EAE1507EA5B6C44C9D042', G:'EE9F6C2DC61F9445DE44089982A4A89066BB61B7AE15D7DCD380226ABB255DD6', T:'8390AC6AF685109F772E54A28576918E5958870E0599E600BAD3E204E7A249F3', C:'2F1555B41F45BD5F7497F3FD89E6092095E0186ACA7DB5A6F1F1082C30E2B62A', S:'5D42A66DB14DB9023892295D351ECAAA1192308F7392754B9A7B15FE02065821', B:'F1567AEC6CE6B54504EA8247E7C76C9965A4CD3EF4A11C8892296CB95F044643', L:'60939D16EBCB078BB77B9CBC29C6AA12706BFB2CEC48B0990CC5C0780F9F4053'}

def require(ok,reason):
    if not ok: raise RuntimeError(reason)
def sha(raw): return hashlib.sha256(raw).hexdigest().upper()
def pick(nodes,name):
    items=[n for n in nodes if getattr(n,'name',None)==name]; require(len(items)==1,'L23_SYMBOL:'+name);return items[0]
def execute(nodes,ns):
    import __future__
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),'<L23-extracted>','exec',flags=__future__.annotations.compiler_flag,dont_inherit=True),ns)
class ForbiddenIO(BaseException): pass
class Forbidden:
    def __getattr__(self,name): raise ForbiddenIO('UNEXPECTED_DEPENDENCY:'+name)
class Logger:
    def info(self,*a,**kw): pass
    def error(self,*a,**kw): pass
    def warning(self,*a,**kw): pass
    def exception(self,*a,**kw): pass

class Fixture:
    def __init__(self,sources,mode):
        self.mode=mode; self.close_entered=asyncio.Event();self.release_close=asyncio.Event();self.ready=asyncio.Event();self.lease_entered=asyncio.Event();self.pool_entered=asyncio.Event();self.release_pool=asyncio.Event();self.pools=0;self.closes=0;self.signals={};self.worker=None;self.close_calls=[]
        outer=self
        async def setup(conn): raise ForbiddenIO('REAL_SETUP')
        class Pool:
            async def close(self):
                outer.closes+=1;outer.close_calls.append(asyncio.current_task());outer.close_entered.set()
                if mode in ('resource_fatal','resource_nominal','supervisor_cleanup_cancel'): raise asyncio.CancelledError('synthetic resource cancellation')
                if mode in ('caller_nominal','caller_fatal'): await outer.release_close.wait()
        async def create_pool(**kw):
            require(kw.get('setup') is setup and kw.get('dsn')=='synthetic-only','L23_POOL_CALIBRATION')
            outer.pools+=1;outer.pool_entered.set()
            if mode=='concurrent_start':await outer.release_pool.wait()
            return Pool()
        def local_import(name,globals=None,locals=None,fromlist=(),level=0):
            if name=='app.postgres_identity' and level==0 and tuple(fromlist)==('worker_connection_setup',):return types.SimpleNamespace(worker_connection_setup=setup)
            raise ForbiddenIO('UNEXPECTED_IMPORT:'+name)
        ns=dict(__builtins__=dict(vars(builtins),__import__=local_import),asyncio=asyncio,asyncpg=types.SimpleNamespace(create_pool=create_pool),logger=Logger(),os=types.SimpleNamespace(getenv=lambda *a:'synthetic-only',environ={}),httpx=Forbidden(),json=Forbidden())
        execute([pick(ast.parse(sources[I]).body,'DatabaseIdentityError'),pick(ast.parse(sources[G]).body,'StrictProviderBarrierError')],ns)
        tree=ast.parse(sources[W]);worker=pick(tree.body,'OutboxWorker')
        wanted={'__init__','start','stop','_process_loop','_observe_bg_task','wait_until_stopped','is_healthy'}
        worker.body=[n for n in worker.body if getattr(n,'name',None) in wanted]
        require({n.name for n in worker.body}>=wanted-{'is_healthy'},'L23_LIFECYCLE_SYMBOLS')
        execute([pick(tree.body,n) for n in ('DispatchAuthorizationError','DispatchExecutionBarrierError','_dq_has_authority_denial_in_chain','_dq_has_execution_barrier_in_chain')]+[worker],ns)
        self.cls=ns['OutboxWorker'];self.fault=ns['DatabaseIdentityError']('synthetic fatal identity denial')
        self.fatal=mode in ('resource_fatal','caller_fatal','health_fatal','supervisor_fatal','supervisor_race','supervisor_cleanup_cancel')
        self.sources=sources
    def build(self,**kwargs):
        outer=self
        class Gate:
            async def authorize_before_dispatch(self,event):raise ForbiddenIO('UNEXPECTED_GATE')
        w=self.cls(dsn=kwargs.get('dsn','synthetic-only'),worker_id='L23-probe',authorization_gate=Gate(),shutdown_timeout=0.08)
        async def lease():
            outer.lease_entered.set();await outer.ready.wait()
            if outer.fatal:raise outer.fault
            await asyncio.Event().wait()
        async def forbidden(*a,**kw):raise ForbiddenIO('UNEXPECTED_PERSISTENCE_OR_DISPATCH')
        w._acquire_lease=lease
        for n in ('_dispatch_event','_mark_authorization_denied','_handle_authorization_failure','_mark_completed','_handle_failure'):setattr(w,n,forbidden)
        self.worker=w;return w
    async def start(self):
        w=self.build();await w.start();await asyncio.wait_for(self.lease_entered.wait(),1);return w
    async def finish_fatal(self,w,remove_callback=False):
        if remove_callback:require(w._bg_task.remove_done_callback(w._observe_bg_task)==1,'L23_CALLBACK_CALIBRATION')
        self.ready.set();done,_=await asyncio.wait({w._bg_task},timeout=1)
        require(w._bg_task in done and not w._bg_task.cancelled() and w._bg_task.exception() is self.fault,'L23_FAULT_CALIBRATION')
        if not remove_callback:await asyncio.sleep(0)
    def main(self):
        # Both platform branches are intercepted; no OS signal handlers are installed.
        def register(sig,callback,*args):
            self.signals[sig]=lambda:callback(*args)
            if sig==signal.SIGTERM:
                self.ready.set()
                if self.mode in ('supervisor_signal','supervisor_race'):
                    asyncio.get_running_loop().call_soon(self.signals[sig])
        sig=types.SimpleNamespace(SIGINT=signal.SIGINT,SIGTERM=signal.SIGTERM,signal=lambda s,cb:register(s,cb,s,None))
        class AsyncFacade:
            def __getattr__(inner,n):return getattr(asyncio,n)
            def get_running_loop(inner):return types.SimpleNamespace(add_signal_handler=register)
        class Env:
            def __getitem__(inner,key):return 'synthetic-only'
        ns=dict(asyncio=AsyncFacade(),signal=sig,sys=types.SimpleNamespace(platform='win32'),os=types.SimpleNamespace(environ=Env(),getenv=lambda k,d=None:d,getpid=lambda:1),logger=Logger(),OutboxWorker=self.build)
        execute([pick(ast.parse(self.sources[E]).body,'main')],ns);return ns['main']
    async def drain(self):
        # Test-only safety net. A probe checks ownership before this runs.
        self.ready.set();self.release_close.set();self.release_pool.set()
        w=self.worker
        tasks={t for t in (getattr(w,'_bg_task',None),getattr(w,'_close_task',None),*self.close_calls) if isinstance(t,asyncio.Task) and t is not asyncio.current_task()}
        for t in tasks:
            if not t.done():t.cancel()
        if tasks:await asyncio.wait_for(asyncio.gather(*tasks,return_exceptions=True),1)

async def outcome(coro):
    try:await coro;return None
    except (Exception,asyncio.CancelledError) as exc:return exc

async def probe(sources,mode):
    f=Fixture(sources,mode);w=None; tasks=set()
    try:
        if mode.startswith('supervisor_'):
            t=asyncio.create_task(f.main()());tasks.add(t)
            done,_=await asyncio.wait({t},timeout=0.25)
            completed=t in done
            if not completed:t.cancel()
            err=await outcome(t)
            require(f.worker is not None and f.pools==1 and f.closes==1,'L23_SUPERVISOR_CALIBRATION')
            require(f.worker._bg_task is None or f.worker._bg_task.done(),'L23_SUPERVISOR_TASK_LEAK')
            return (completed,err is f.fault,type(err).__name__ if err else 'NONE')
        if mode=='concurrent_start':
            w=f.build();a=asyncio.create_task(w.start());tasks.add(a)
            await asyncio.wait_for(f.pool_entered.wait(),1)
            b=asyncio.create_task(w.start());tasks.add(b);await asyncio.sleep(0)
            f.release_pool.set();x=await outcome(a);y=await outcome(b);z=await outcome(w.stop())
            return (x is None,isinstance(y,RuntimeError),f.pools,f.closes,z is None)
        if mode=='health_prestart_cancel':
            w=f.build();await w.start();first=w._bg_task
            require(first.remove_done_callback(w._observe_bg_task)==1,'L23_PRESTART_CALLBACK')
            first.cancel();done,_=await asyncio.wait({first},timeout=1)
            require(first in done and first.cancelled(),'L23_TRUE_TASK_CANCEL_CALIBRATION')
            healthy=getattr(w,'is_healthy',None);err=await outcome(w.stop());return (healthy,isinstance(err,RuntimeError))
        w=await f.start();first=w._bg_task
        if mode=='health_fatal':
            await f.finish_fatal(w,True)
            healthy=getattr(w,'is_healthy',None)
            err=await outcome(w.stop());return (healthy,err is f.fault)
        if mode=='health_cancelled':
            first.remove_done_callback(w._observe_bg_task);first.cancel()
            done,_=await asyncio.wait({first},timeout=1);require(first in done,'L23_CANCEL_CALIBRATION')
            healthy=getattr(w,'is_healthy',None);err=await outcome(w.stop());return (healthy,isinstance(err,RuntimeError))
        if f.fatal:await f.finish_fatal(w)
        if mode in ('resource_fatal','resource_nominal'):
            err=await outcome(w.stop());require(f.closes==1,'L23_CLOSE_CALIBRATION')
            return (err is f.fault if f.fatal else isinstance(err,RuntimeError),type(err).__name__ if err else 'NONE',w._fatal_error is f.fault if f.fatal else w._fatal_error is None)
        if mode.startswith('caller_'):
            t=asyncio.create_task(w.stop());tasks.add(t)
            await asyncio.wait_for(f.close_entered.wait(),1);t.cancel();err=await outcome(t)
            owned=getattr(w,'_close_task',None) is f.close_calls[0] and not f.close_calls[0].done()
            f.release_close.set();err2=await outcome(w.stop())
            return (isinstance(err,asyncio.CancelledError),owned,f.closes,err2 is f.fault if f.fatal else err2 is None,w.pool is None,all(t.done() or t is asyncio.current_task() for t in f.close_calls))
        if mode=='wait_after_stop':
            err=await outcome(w.stop());wait=await outcome(w.wait_until_stopped());return (err is None,wait is None)
        if mode=='observer_cancel':
            t=asyncio.create_task(w.wait_until_stopped());tasks.add(t);await asyncio.sleep(0);t.cancel();err=await outcome(t)
            alive=not first.done();stop=await outcome(w.stop());return (isinstance(err,asyncio.CancelledError),alive,stop is None)
        raise RuntimeError('L23_UNKNOWN_MODE')
    finally:
        for t in tasks:
            if not t.done():t.cancel()
        if tasks:await asyncio.wait_for(asyncio.gather(*tasks,return_exceptions=True),1)
        await f.drain()

EXPECT={
 'resource_fatal':(True,'DatabaseIdentityError',True),
 'resource_nominal':(True,'RuntimeError',True),
 'caller_nominal':(True,True,1,True,True,True),
 'caller_fatal':(True,True,1,True,True,True),
 'health_fatal':(False,True), 'health_cancelled':(False,True), 'health_prestart_cancel':(False,True),
 'wait_after_stop':(True,True), 'observer_cancel':(True,True,True),
 'concurrent_start':(True,True,1,1,True),
 'supervisor_fatal':(True,True,'DatabaseIdentityError'),
 'supervisor_cleanup_cancel':(True,True,'DatabaseIdentityError'),
 'supervisor_signal':(True,False,'NONE'),
 'supervisor_race':(True,True,'DatabaseIdentityError'),
}
RED_EXPECT={
 'resource_fatal':(False,'CancelledError',True),
 'resource_nominal':(False,'CancelledError',True),
 'caller_nominal':(True,False,2,True,True,True),
 'caller_fatal':(True,False,2,True,True,True),
 'health_fatal':(None,True),'health_cancelled':(None,True),'health_prestart_cancel':(None,True),
 'wait_after_stop':(True,False),'supervisor_fatal':(False,True,'DatabaseIdentityError'),
 'supervisor_cleanup_cancel':(False,False,'CancelledError'),
}
def suite_for(sources,receipts):
    class Cases(unittest.TestCase):pass
    def make(mode):
        def test(self):
            result=asyncio.run(probe(sources,mode));receipts[mode]=result;print('L23_PROBE='+mode+' '+repr(result),flush=True);self.assertEqual(result,EXPECT[mode])
        return test
    for mode in EXPECT:setattr(Cases,'test_'+mode,make(mode))
    return unittest.defaultTestLoader.loadTestsFromTestCase(Cases)

def run_suite(sources,red=False):
    receipts={}
    result=unittest.TextTestRunner(verbosity=2).run(suite_for(sources,receipts))
    require(result.testsRun==len(EXPECT) and not result.errors and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses,'L23_SUITE_INCONCLUSIVE')
    if red:
        require({t._testMethodName for t,_ in result.failures}=={'test_'+m for m in RED_EXPECT},'L23_RED_SET')
        require(all(receipts[m]==v for m,v in RED_EXPECT.items()),'L23_RED_SIGNATURE')
        print('L23_EXPECTED_RED_10_FAIL_4_PASS')
    else:
        require(result.wasSuccessful(),'L23_GREEN_REQUIRED');print('L23_GREEN_14_OF_14_PASS')


SOURCE_SETS=[{'app/outbox_worker.py': '6C8F03FF475DAC725B13CA6672E577E46FE82BF063E8E8B767720032D3F7B843', 'app/run_worker.py': '2E453E3F31155AE074AB3426FD25E0826323829533F7948F1F3D53D6808BBA8C', 'app/postgres_identity.py': '1D7CAB504A20C0A7A864948491C6FB107BF0F610036EAE1507EA5B6C44C9D042', 'app/auth/provider_dispatch_gate.py': 'EE9F6C2DC61F9445DE44089982A4A89066BB61B7AE15D7DCD380226ABB255DD6'}, {'app/outbox_worker.py': 'D332DB4EB01929590F56A1E70558F11AB59CC18EB3DE538FB399B4DEB632D562', 'app/run_worker.py': '7C1B7F19AEAC2290AD9B01A4C7C4CFD136348881333C265CEB654BD9FDE3B230', 'app/postgres_identity.py': '1D7CAB504A20C0A7A864948491C6FB107BF0F610036EAE1507EA5B6C44C9D042', 'app/auth/provider_dispatch_gate.py': 'EE9F6C2DC61F9445DE44089982A4A89066BB61B7AE15D7DCD380226ABB255DD6'}]
def load_sources():
    root=Path(__file__).resolve().parents[1]
    sources={p:(root/p).read_bytes() for p in (W,E,I,G)}
    actual={p:sha(v) for p,v in sources.items()}
    require(actual in SOURCE_SETS,'L23_UNREVIEWED_SOURCE_SET')
    return sources,actual==SOURCE_SETS[0]
def load_tests(loader, tests, pattern):
    sources,_=load_sources()
    return suite_for(sources,{})
if __name__=='__main__':
    require(__debug__,'L23_OPTIMIZED_MODE_FORBIDDEN')
    sources,baseline=load_sources()
    if sys.argv[1:] in (['--supervisor-child-fatal'],['--supervisor-child-signal']):
        require(not baseline,'L23_CHILD_GREEN_ONLY')
        mode='supervisor_fatal' if sys.argv[1].endswith('fatal') else 'supervisor_signal'
        async def child():
            f=Fixture(sources,mode)
            try:
                await asyncio.wait_for(f.main()(),1)
                require(mode=='supervisor_signal','L23_CHILD_FATAL_NOT_RAISED')
            except Exception as exc:
                require(mode=='supervisor_fatal' and exc is f.fault,'L23_CHILD_PRIMARY_IDENTITY')
                print('L23_CHILD_FATAL_IDENTITY_VERIFIED',flush=True)
                raise
            finally:
                require(f.closes==1,'L23_CHILD_CLEANUP')
                await f.drain()
        asyncio.run(child())
        print('L23_CHILD_GRACEFUL_EXIT')
    else:
        require(sys.argv[1:] in ([],['--expect-red-baseline']),'L23_TEST_ARGUMENT')
        require(baseline==bool(sys.argv[1:]),'L23_TEST_MODE_MISMATCH')
        run_suite(sources,baseline)
