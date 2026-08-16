import ubin

with ubin.open("sample.surya123") as data:
    print("Name:", data.name)
    print("Size:", data.size)
    print("Type:", data.type)
    print("Info:", data.info())

    print("First bytes:", data.read(20))
    print("SHA-256:", data.hash())