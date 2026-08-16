import ubin

secured = ubin.secure("sample.surya123")
receipt = secured.save("sample.ubs", overwrite=True)

print("Secure file:", receipt.output)
print("Original size:", receipt.original_size)
print("Frames:", receipt.frame_count)
print("Original SHA-256:", receipt.sha256)

restored = ubin.decrypt(
    "sample.ubs",
    "sample_restored.surya123",
    key=receipt.key,
    overwrite=True,
)

print("Restored file:", restored.output)
print("Restored SHA-256:", restored.sha256)
print("MATCH:", restored.sha256 == receipt.sha256)
