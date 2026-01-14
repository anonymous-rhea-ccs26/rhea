from typing import List

BITS = 8

def int2bits(foo : int) -> List[int]:
    return [foo >> i & 1 for i in range(BITS-1, -1, -1)]

def list2str(foo):
    foo = list(map(str, foo))
    return ", ".join(foo)

if __name__ == "__main__":
    print(f"int2bits 0 : {int2bits(0)}")
    print(f"int2bits 1 : {int2bits(1)}")
    print(f"int2bits 255 : {int2bits(255)}")
