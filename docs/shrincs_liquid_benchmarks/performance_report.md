# SHRINCS-L. On-Liquid Performance Report
```
General params: n=16, w=4, l=64, S_wn=140, h_sf=207, h_sl=24, d=2, k=6, a=22, R_SIZE=32

Keys size:

    Seed (backup):  48 bytes
    Secret key:     96 bytes
    Public key:     32 bytes

Stateful signature:

    |  q| size, bytes | witness, vBytes | hash ops |   kWU   |  fee, $  | sat/vB |
    -----------------------------------------------------------------------------
    |  1|    1092     |      9439       |    55    |  37.755 |    0.6   |  0.11  |
    -----------------------------------------------------------------------------
    |  2|    1108     |      9444       |    56    |  37.774 |   0.82   |  0.13  |
    -----------------------------------------------------------------------------
    | 10|    1236     |      9612       |    64    |  38.445 |   0.68   |  0.10  |
    -----------------------------------------------------------------------------
    |100|    2676     |     11337       |   154    |  45.345  |  0.89   |  0.11  |

Stateless signature:

    | size, bytes | witness, vBytes | hash ops |    kWU   |  fee, $  | sat/vB |
    --------------------------------------------------------------------------
    |    4396     |      23113      |    247   |  92.450  |   1.59   |  0.10  |

Signing and verification time:

    Stateful signing time:                  3742.92 ms
    Stateful verification time (local):     0.015506 ms
    Stateless signing time:                 17974.8 ms
    Stateless verification time (local):    0.073762 ms

Machine: Intel Core i5, 16 GB RAM

```
> Notes: Liquid requires the transaction size to be proportional to the computational units it spends. Instead of padding it with random or "0" bytes, we filled it with the Bitcoin Whitepaper.

Transactions:

TX (`q=1`): https://blockstream.info/liquid/tx/e079f31c58655e7b37477c6bb8f23aafaa942a86fe8c47f2970840a2c0829239

TX (`q=2`): https://blockstream.info/liquid/tx/eb0ccf008d06b6f5154180dd2c752af814be00c6d994ed4324341a27b0d20f8c

TX (`q=10`): https://blockstream.info/liquid/tx/f7062c49aeff73409183f1de36c07aa79b8a1b2eb0f1a742c494d3df98ad98f3

TX (`q=100`): https://blockstream.info/liquid/tx/375ebd818b7ec093e59f2a94d2e4277d6b9a260c0f09743c839120dcc0dc1cb5

TX (`stateless`): https://blockstream.info/liquid/tx/f4a108b362392f18627f008bd752010ee00bb215a83ccc2b59ca5b690e54d1c2