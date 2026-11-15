"""Independent contract checks. Run only after frozen API/source review."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from itsdangerous import BadSignature, TimedSerializer, TimestampSigner, URLSafeTimedSerializer
from itsdangerous import MigratingTimedSerializer, SigningScheme, URLSafeMigratingTimedSerializer

class Clock:
    def __init__(self, value): self.value=value; self.calls=0
    def __call__(self): self.calls+=1; return self.value

class BodyCodec:
    def __init__(self): self.loads_calls=0
    def dumps(self,value,**kwargs): return json.dumps(value,**kwargs)
    def loads(self,value): self.loads_calls+=1; return json.loads(value)

def scheme(id='old', key='local-test-key-a', salt='purpose-a', start=100, stop=200, retire=300, **kw):
    return SigningScheme(id=id,secret_key=key,salt=salt,valid_from=start,valid_to=stop,retire_at=retire,**kw)

def token(stamp=150,key='local-test-key-a',salt='purpose-a',body=None,urlsafe=False,**kwargs):
    class AtTime(TimestampSigner):
        def get_timestamp(self): return stamp
    cls=URLSafeTimedSerializer if urlsafe else TimedSerializer
    return cls(key,salt=salt,signer=AtTime,signer_kwargs=kwargs).dumps({'account':'test-user'} if body is None else body)

def reader(schemes=None,now=250,codec=None,current='old',urlsafe=False):
    clock=Clock(now);cls=URLSafeMigratingTimedSerializer if urlsafe else MigratingTimedSerializer
    value=cls([scheme()] if schemes is None else schemes,current,clock=clock,serializer=codec)
    clock.calls=0
    return value,clock

def test_old_signature_and_reported_identity():
    codec=BodyCodec();r,c=reader(codec=codec)
    body,id=r.loads_migration(token(),max_age=100)
    assert body=={'account':'test-user'} and id=='old'
    assert c.calls==1 and codec.loads_calls==1
    assert 'local-test-key' not in repr((body,id))

@pytest.mark.parametrize('stamp,accepted',[(99,False),(100,True),(199,True),(200,False),(220,False)])
def test_real_signed_issuance_edges(stamp,accepted):
    codec=BodyCodec();r,c=reader(codec=codec)
    if accepted:r.loads_migration(token(stamp))
    else:
        with pytest.raises(BadSignature):r.loads_migration(token(stamp))
    assert codec.loads_calls==int(accepted) and c.calls==1

@pytest.mark.parametrize('now,accepted',[(299,True),(300,False),(301,False)])
def test_retirement_exact_moment(now,accepted):
    codec=BodyCodec();r,c=reader(now=now,codec=codec)
    if accepted:r.loads_migration(token())
    else:
        with pytest.raises(BadSignature):r.loads_migration(token())
    assert codec.loads_calls==int(accepted) and c.calls==1

@pytest.mark.parametrize('age,accepted',[(100,True),(99,False)])
def test_maximum_age_edge(age,accepted):
    r,c=reader()
    if accepted:r.loads_migration(token(),max_age=age)
    else:
        with pytest.raises(BadSignature):r.loads_migration(token(),max_age=age)
    assert c.calls==1

@pytest.mark.parametrize('skew,accepted',[(1,True),(0,False)])
def test_future_tolerance_edge(skew,accepted):
    codec=BodyCodec();r,_=reader(now=149,codec=codec)
    if accepted:r.loads_migration(token(),future_tolerance=skew)
    else:
        with pytest.raises(BadSignature):r.loads_migration(token(),future_tolerance=skew)
    assert codec.loads_calls==int(accepted)

def test_same_key_different_salts_return_actual_scheme():
    r,c=reader([scheme(id='other',salt='other-purpose'),scheme()])
    assert r.loads_migration(token())[1]=='old' and c.calls==1

def test_overlapping_scheme_checks_are_indivisible():
    a=scheme(id='key-a',stop=140)
    b=scheme(id='key-b',key='local-test-key-b',start=100,stop=200)
    codec=BodyCodec();r,c=reader([a,b],codec=codec,current='key-b')
    with pytest.raises(BadSignature):r.loads_migration(token())
    assert codec.loads_calls==0 and c.calls==1

def test_later_complete_candidate_can_succeed():
    a=scheme(id='expired-window',stop=140)
    b=scheme(id='allowed-window')
    r,c=reader([a,b],current='allowed-window')
    assert r.loads_migration(token())[1]=='allowed-window' and c.calls==1

def test_bad_mac_never_parses_body():
    codec=BodyCodec();r,c=reader(codec=codec)
    with pytest.raises(BadSignature):r.loads_migration(token(key='untrusted-test-key'))
    assert codec.loads_calls==0 and c.calls==1

def test_scheme_signer_arguments_are_copied():
    args={'digest_method':hashlib.sha256};s=scheme(signer_kwargs=args)
    args['digest_method']=hashlib.sha1
    r,_=reader([s]);assert r.loads_migration(token(digest_method=hashlib.sha256))[1]=='old'

def test_caller_scheme_list_cannot_retarget_reader():
    values=[scheme()];r,_=reader(values);values[:]=[scheme(key='replacement-test-key')]
    assert r.loads_migration(token())[1]=='old'

def test_independent_concurrent_clocks():
    barrier=Barrier(2)
    def work(now,expected):
        r,c=reader(now=now);barrier.wait()
        try:r.loads_migration(token(),max_age=100);accepted=True
        except BadSignature:accepted=False
        assert accepted is expected and c.calls==1
        return accepted
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(work,250,True);b=pool.submit(work,251,False)
        assert (a.result(),b.result())==(True,False)

def test_urlsafe_real_signature():
    r,c=reader(urlsafe=True)
    assert r.loads_migration(token(urlsafe=True))[0]=={'account':'test-user'} and c.calls==1

def test_new_issuance_only_uses_explicit_current_scheme():
    class At170(TimestampSigner):
        def get_timestamp(self): return 170
    a=scheme();b=scheme(id='new',key='new-test-key',salt='new-purpose',start=160,stop=280)
    r=MigratingTimedSerializer([a,b],'new',clock=lambda:250,signer=At170)
    encoded=r.dumps({'new':True})
    assert r.loads_migration(encoded)==({'new':True},'new')
    with pytest.raises(BadSignature):TimedSerializer('local-test-key-a',salt='purpose-a').loads(encoded)

@pytest.mark.parametrize('bad_clock',[None,0,'clock'])
def test_noncallable_clock_rejected_at_configuration(bad_clock):
    with pytest.raises((TypeError,ValueError)):MigratingTimedSerializer([scheme()],'old',clock=bad_clock)

def test_empty_and_duplicate_configuration_rejected():
    with pytest.raises((TypeError,ValueError)):MigratingTimedSerializer([],'old')
    with pytest.raises((TypeError,ValueError)):MigratingTimedSerializer([scheme(),scheme()],'old')
    with pytest.raises((TypeError,ValueError)):scheme(start=200,stop=100)

def test_default_timed_serializer_still_works():
    r=TimedSerializer('ordinary-test-key');body={'ordinary':True}
    assert r.loads(r.dumps(body),max_age=10)==body
