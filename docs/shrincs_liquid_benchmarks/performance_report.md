# SHRINCS-L. On-Liquid Performance Report
```
General params: n=16, w=4, l=64, S_wn=140, h_sf=205, h_sl=24, d=2, k=6, a=22, R_SIZE=32

Keys size:

    Seed (backup):  48 bytes
    Secret key:     96 bytes
    Public key:     32 bytes

Stateful signature:

    |  q| size, bytes | witness, vBytes | hash ops |   kWU   |  fee, $  |
    -----------------------------------------------------------------
    |  1|    1092     |      9439       |    55    |  37.755 |    0.6   |
    -----------------------------------------------------------------
    |  2|    1108     |        ?        |    56    |  ?  |     ?    |
    -----------------------------------------------------------------
    | 10|    1236     |        ?        |    64    |  ?  |     ?    |
    -----------------------------------------------------------------
    |100|    2676     |        ?        |   154    |  ?  |     ?    |

Stateless signature:

    | size, bytes | witness, vBytes | hash ops | kWU |  fee, $  |
    -------------------------------------------------------------
    |    7848     |        ?        |    422   |  ?  |     ?    |

Signing and verification (locally) time:

    Stateful signing time:          3742.92 ms
    Stateful verification time:     0.015506 ms
    Stateless signing time:         17974.8 ms
    Stateless verification time:    0.073762 ms

Machine: Intel Core i5, 16 GB RAM

```
> Notes: Liquid requires the transaction size to be proportional to the computational units it spends. Instead of padding it with random or "0" bytes, we filled it with the Bitcoin Whitepaper.

TX to fund the init address: https://blockstream.info/liquid/tx/ed9c2a0b43f2462d02c259759d0288200c891b028a218718ea6a7d805ff4d308










