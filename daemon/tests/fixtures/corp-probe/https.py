"""Shared fixed-host HTTPS transcript on the fixture's existing stream."""
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(CERT_PATH, KEY_PATH)
context.set_alpn_protocols(["http/1.1"])


def sni(_socket, name, _context):
    assert name == "admin.corp.ninitux.com"


context.set_servername_callback(sni)
stream = context.wrap_socket(stream, server_side=True)
assert stream.selected_alpn_protocol() == "http/1.1"
request = b""
while b"\r\n\r\n" not in request:
    assert len(request) <= 8192
    request += exact(stream, 1)
lines = request.decode("ascii").split("\r\n")
assert lines[0] == "POST /api/v1/corp/egress-observation HTTP/1.1"
fields = {}
for line in lines[1:]:
    if line:
        key, value = line.split(":", 1)
        key = key.lower()
        assert key not in fields
        fields[key] = value.strip()
assert fields["host"] == "admin.corp.ninitux.com"
assert fields["content-length"] == "0"
assert fields["connection"].lower() == "close"
assert set(fields) == {"host", "authorization", "content-length", "connection"}
assert fields["authorization"].startswith("Bearer ")
token = fields["authorization"][7:]
event("request", token=token)
status = "302 Found" if MODE == "redirect" else "204 No Content"
echo = "wrong" if MODE == "wrong_echo" else token
headers = ["HTTP/1.1 " + status]
if MODE != "missing_echo":
    headers.append("x-CoRp-PrObE: " + echo)
if MODE == "duplicate_echo":
    headers.append("X-Corp-Probe: " + token)
if MODE == "large_headers":
    headers.append("X-Padding: " + "x" * 8192)
if MODE == "many_headers":
    headers.extend("X-%d: value" % number for number in range(65))
if MODE == "transfer_encoding":
    headers.append("Transfer-Encoding: chunked")
if MODE == "nonzero_length":
    headers.append("Content-Length: 1")
elif MODE == "duplicate_length":
    headers.extend(["Content-Length: 0", "Content-Length: 0"])
elif MODE != "absent_length":
    headers.append("Content-Length: 0")
if MODE == "redirect":
    headers.append("Location: https://example.invalid/never-follow")
response = ("\r\n".join(headers) + "\r\n\r\n").encode()
if MODE == "body":
    response += b"forbidden-body"
if MODE == "trickle":
    for byte in response:
        assert control.recv(1) == b"x"
        stream.sendall(bytes([byte]))
    sys.exit(0)
stream.sendall(response)
event("response_sent")
while control.recv(1):
    pass
