import ubin

server = ubin.secure_server(
    host="127.0.0.1",
    port=9443,
    certfile="server-cert.pem",
    keyfile="server-key.pem",
    output_dir="received",
)

print("Listening on port", server.port)
print(server.serve_once())
