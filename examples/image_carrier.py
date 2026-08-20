import ubin

passphrase = "replace-with-a-long-private-passphrase"

packed = ubin.to_image(
    "sample.surya123",
    "sample.ubin.png",
    passphrase=passphrase,
)
print("Carrier:", packed.output)
print("SHA-256:", packed.sha256)

restored = ubin.from_image(
    "sample.ubin.png",
    "sample-restored.surya123",
    passphrase=passphrase,
)
print("Restored:", restored.output)
