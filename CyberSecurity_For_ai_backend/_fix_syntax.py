c = open('security_layer.py', 'rb').read()
for line in c.split(b'\n'):
    if b'reasons' in line and b'join' in line:
        print('actual bytes:', repr(line))

# Fix it
bad  = b"        reasons = \"; \".join(f[\\\'reason\\\'] for f in flagged[:3])"
good = b'        reasons = "; ".join(f["reason"] for f in flagged[:3])'
print("count:", c.count(bad))
c2 = c.replace(bad, good)
open('security_layer.py', 'wb').write(c2)
print("done")
