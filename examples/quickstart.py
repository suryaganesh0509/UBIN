import ubin

with ubin.open("sample.surya123") as obj:
    print(obj.info())
    print("SHA-256:", obj.hash())
