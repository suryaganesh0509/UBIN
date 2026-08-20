"""Small public smoke example for UBIN v1.0.2."""
import ubin


def main():
    with ubin.open(b"Hello UBIN", name="example.custom") as obj:
        print(obj.info())
        print("SHA-256:", obj.hash())


if __name__ == "__main__":
    main()
