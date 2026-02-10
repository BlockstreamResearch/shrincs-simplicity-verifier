# SHRINCS-L. On-Liquid Performance Report
```
General params: n=16, w=4, l=64, S_wn=140, h_sf=418, d=5, h'=8, k=6, a=22

Keys size:

    Seed (backup):  48 bytes
    Secret key:     96 bytes
    Public key:     32 bytes

Stateful signature:

    |  q| size, bytes | witness, vbytes | hash ops | kWU |  fee, $  |
    -----------------------------------------------------------------
    |  1|    1092     |        ?        |    55    |  ?  |     ?    |
    -----------------------------------------------------------------
    |  2|    1108     |        ?        |    56    |  ?  |     ?    |
    -----------------------------------------------------------------
    | 10|    1236     |        ?        |    64    |  ?  |     ?    |
    -----------------------------------------------------------------
    |100|    2676     |        ?        |   154    |  ?  |     ?    |
    -----------------------------------------------------------------
    |418|    7764     |        ?        |   472    |  ?  |     ?    |

Stateless signature:

    | size, bytes | witness, vbytes | hash ops | kWU |  fee, $  |
    -------------------------------------------------------------
    |    7848     |        ?        |    422   |  ?  |     ?    |

Signing cost:

    Stateful(WOTS+C):                  4.1m (X seconds)
    Stateless(FORS+C + 5x WOTS+C):     24.5m (X seconds)

Machine: 
```










