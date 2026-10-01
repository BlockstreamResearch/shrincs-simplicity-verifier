#!/usr/bin/env python3
"""Plain-Python reference of the SHRINCS-L stateful verification (same hash layouts as the Simplicity verifier)."""
import hashlib, json, sys

HSF = 206

def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def adrs(layer, tree1, tree2, typ, w1, w2, w3) -> bytes:
    return layer.to_bytes(4, 'big') + tree1.to_bytes(4, 'big') + tree2.to_bytes(8, 'big') + typ.to_bytes(4, 'big') + w1.to_bytes(4, 'big') + w2.to_bytes(4, 'big') + w3.to_bytes(4, 'big')

def tw(seed: bytes, a: bytes, m: bytes) -> bytes:
    """Tweaked hash: SHA256(seed || 0^48 || ADRS || m), truncated to 16 bytes."""
    return H(seed + bytes(48) + a + m)[:16]

def digits_of(msg16: bytes):
    x = int.from_bytes(msg16, 'big')
    return [(x >> (126 - 2 * i)) & 3 for i in range(64)]

def verify_stateful(message: bytes, seed: bytes, root: bytes, q: int, r: bytes, counter: int, sig: list, path: list, sl_root: bytes, trace=None):
    key_idx = q
    msg1 = H(adrs(0, 0, 0, 4, 0, 0, 0) + r + seed + root + message)[:16]
    msg = H(adrs(0, 0, 0, 3, key_idx, 0, 0) + seed + msg1 + counter.to_bytes(4, 'big'))[:16]
    d = digits_of(msg)
    if sum(d) != 140:
        return False, 'checksum'
    pks = []
    for i in range(64):
        x = sig[i]
        for k in range(d[i], 3):
            x = tw(seed, adrs(0, 0, 0, 0, key_idx, i, k), x)
        pks.append(x)
    leaf = tw(seed, adrs(0, 0, 0, 1, key_idx, 0, 0), b''.join(pks))
    if trace is not None:
        trace.update(msg1=msg1.hex(), msg=msg.hex(), digits=d, pks=[p.hex() for p in pks], leaf=leaf.hex())
    node = leaf
    if key_idx == 207:
        h = 1
        node = tw(seed, adrs(0, 0, 0, 2, 0, h, 0), path[0] + node)
    else:
        h = 207 - key_idx
        node = tw(seed, adrs(0, 0, 0, 2, 0, h, 0), node + path[0])
    h += 1
    for a in path[1:]:
        node = tw(seed, adrs(0, 0, 0, 2, 0, h, 0), a + node)
        h += 1
    if trace is not None:
        trace.update(uxmss_root=node.hex())
    final = tw(seed, adrs(0, 0, 0, 16, 0, 0, 0), node + sl_root)
    return final == root, final.hex()

def parse_vector(rec, key):
    sig_hex = rec['sig']
    b = bytes.fromhex(sig_hex)
    sl_root = b[:16]; r = b[16:48]; counter = int.from_bytes(b[48:52], 'big')
    sig = [b[52 + 16 * i: 68 + 16 * i] for i in range(64)]
    path = [b[1076 + 16 * i: 1092 + 16 * i] for i in range((len(b) - 1076) // 16)]
    return dict(message=bytes.fromhex(rec['message']), seed=bytes.fromhex(key['seed']), root=bytes.fromhex(key['root']),
                q=rec['q'], r=r, counter=counter, sig=sig, path=path, sl_root=sl_root)

if __name__ == '__main__':
    key = None; n = 0; ok = 0
    for line in open(sys.argv[1]):
        rec = json.loads(line)
        if rec['kind'] == 'key':
            key = rec; continue
        if rec['kind'] != 'stateful':
            continue
        v = parse_vector(rec, key)
        res, _ = verify_stateful(**v)
        n += 1; ok += res
    print(f'reference verifier: {ok}/{n} stateful vectors accepted')
