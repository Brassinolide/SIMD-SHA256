# SIMD-SHA256
Header Only SHA256 implement with SIMD instruction

https://crackme.net/articles/simdsha256/

```C++
#include "SIMDSHA256.h"

int main() {
    uint8_t data[] = {"test"};
    uint8_t hash[32]; //9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

    SIMD_SHA256 sha256;
    sha256.update(data, 4);
    sha256.finallize((uint32_t*)hash);

    //Use init() to reset the state before computing the next sha256
    sha256.init();
}
```
