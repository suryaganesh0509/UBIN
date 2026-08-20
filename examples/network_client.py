import ubin

receipt = ubin.secure("sample.surya123").send(
    "127.0.0.1",
    port=9443,
    cafile="server-cert.pem",
    resume=True,
    permutation=True,
)
print(receipt)
