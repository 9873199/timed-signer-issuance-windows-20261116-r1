"""Reviewer-owned demonstration of the frozen migration API."""
from itsdangerous import SigningScheme, MigratingTimedSerializer, TimedSerializer, TimestampSigner, BadSignature

class AtTime(TimestampSigner):
    stamp=150
    def get_timestamp(self): return self.stamp

old=SigningScheme(id='retiring',secret_key='demo-old-key',salt='session',valid_from=100,valid_to=200,retire_at=300)
new=SigningScheme(id='current',secret_key='demo-new-key',salt='session-v2',valid_from=160,valid_to=400,retire_at=500)
clock={'now':250}
reader=MigratingTimedSerializer([old,new],'current',clock=lambda:clock['now'])
writer=TimedSerializer('demo-old-key',salt='session',signer=AtTime)

print('Timed signature migration\n')
AtTime.stamp=150
body,matched=reader.loads_migration(writer.dumps({'account':'example'}),max_age=100)
print('Earlier signed session: ACCEPTED, scheme =',matched)
print('Account:',body['account'])
AtTime.stamp=220
try: reader.loads_migration(writer.dumps({'account':'example'}))
except BadSignature: print('Old key, timestamp beyond issuance window: REJECTED')
AtTime.stamp=150
saved=writer.dumps({'account':'example'})
clock['now']=300
try: reader.loads_migration(saved)
except BadSignature: print('At exact retirement time: REJECTED')
clock['now']=250;AtTime.stamp=170
current=MigratingTimedSerializer([old,new],'current',clock=lambda:250,signer=AtTime)
_,matched=current.loads_migration(current.dumps({'account':'renewed'}))
print('Newly signed session uses scheme:',matched)
print('\nAll displayed checks use real HMAC signatures.')
