with open('api_server.py', 'rb') as f:
    c = f.read()

dash11 = b'\xe2\x94\x80' * 11
dash5  = b'\xe2\x94\x80' * 5

host_key = b'"X-Simulate-IP", request.client.host)'

# Patch 1 — /api/chat (has "Support simulated header" comment)
marker1 = b'Support simulated header for testing)'
i1 = c.find(marker1)
assert i1 != -1, "marker1 not found"
# Find the start of the line
start1 = c.rfind(b'\n', 0, i1) + 1
# Find end: past "check_network_security(client_ip)"
end1 = c.find(b'check_network_security(client_ip)', start1) + len(b'check_network_security(client_ip)')
old1 = c[start1:end1]

new1 = (
    b'    # Extract client IP (Support simulated header for testing)\r\n'
    b'    client_ip = request.headers.get("X-Simulate-IP", request.client.host)\r\n'
    b'    auth_header = request.headers.get("Authorization", "")\r\n'
    b'\r\n'
    b'    # \xe2\x94\x80\xe2\x94\x80 Network Security Check (Rate Limit / TOR / Geo / JWT) ' + dash5 + b'\r\n'
    b'    is_allowed, block_decision, attack_type = check_network_security(client_ip, auth_header)'
)

print("old1:", repr(old1))
print("new1:", repr(new1))

c = c[:start1] + new1 + c[end1:]

# Patch 2 — /api/chat/upload (shorter comment, find AFTER patch1 end)
marker2 = b'    # Extract client IP\r\n'
i2 = c.find(marker2, start1 + len(new1))
assert i2 != -1, "marker2 not found"
end2 = c.find(b'check_network_security(client_ip)', i2) + len(b'check_network_security(client_ip)')
old2 = c[i2:end2]

new2 = (
    b'    # Extract client IP\r\n'
    b'    client_ip = request.headers.get("X-Simulate-IP", request.client.host)\r\n'
    b'    auth_header = request.headers.get("Authorization", "")\r\n'
    b'\r\n'
    b'    # \xe2\x94\x80\xe2\x94\x80 Network Security Check (Rate Limit / TOR / Geo / JWT) ' + dash5 + b'\r\n'
    b'    is_allowed, block_decision, attack_type = check_network_security(client_ip, auth_header)'
)

print("old2:", repr(old2))
c = c[:i2] + new2 + c[end2:]

with open('api_server.py', 'wb') as f:
    f.write(c)
print("DONE — both patches applied")
