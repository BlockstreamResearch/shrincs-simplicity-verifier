#!/usr/bin/env python3
"""Plain-Python reference of the SHRINCS-L stateless (FORS + 2-layer XMSS) verification, same hash layouts as the
Simplicity verifiers. Also exposes the intermediate values (indices, order bits) the witness converter needs.

Usage: ref_verify_sl.py vectors.jsonl      -> checks every stateless vector in the file
"""
import hashlib, json, sys

K_TREES = 5          # FORS trees verified (the 6th index is ground to zero by the signer)
A = 22               # FORS tree height
H_XMSS = 12          # XMSS tree height per layer
D_LAYERS = 2
L = 64               # WOTS chains
DIGIT_SUM = 140

def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def adrs(layer, tree, typ, w1, w2, w3) -> bytes:
    return layer.to_bytes(4, 'big') + tree.to_bytes(12, 'big') + typ.to_bytes(4, 'big') + w1.to_bytes(4, 'big') + w2.to_bytes(4, 'big') + w3.to_bytes(4, 'big')

def tw(seed: bytes, a: bytes, m: bytes) -> bytes:
    return H(seed + bytes(48) + a + m)[:16]

def digits_of(msg16: bytes):
    x = int.from_bytes(msg16, 'big')
    return [(x >> (126 - 2 * i)) & 3 for i in range(64)]

def parse_vector(rec, key):
    b = bytes.fromhex(rec['sig'])
    p = 0
    sf_root = b[p:p + 16]; p += 16
    r = b[p:p + 32]; p += 32
    fors = []
    for _ in range(K_TREES):
        sk = b[p:p + 16]; p += 16
        path = [b[p + 16 * i:p + 16 * i + 16] for i in range(A)]; p += 16 * A
        fors.append((sk, path))
    layers = []
    for _ in range(D_LAYERS):
        xr = b[p:p + 32]; p += 32          # per-layer randomness, not used by the verifier
        counter = int.from_bytes(b[p:p + 4], 'big'); p += 4
        sig = [b[p + 16 * i:p + 16 * i + 16] for i in range(L)]; p += 16 * L
        path = [b[p + 16 * i:p + 16 * i + 16] for i in range(H_XMSS)]; p += 16 * H_XMSS
        layers.append((counter, sig, path))
    assert p == len(b), (p, len(b))
    return dict(message=bytes.fromhex(rec['message']), seed=bytes.fromhex(key['seed']), root=bytes.fromhex(key['root']),
                sf_root=sf_root, r=r, fors=fors, layers=layers)

def digest_indices(seed, root, message, r):
    """Message digest and the derived FORS leaf indices / hypertree index."""
    d = H(adrs(0, 0, 14, 0, 0, 0) + r + seed + root + message)
    x = int.from_bytes(d, 'big')
    idx = [(x >> (256 - 22 * (i + 1))) & 0x3FFFFF for i in range(6)]      # six 22-bit fields from the top
    idx24 = (x >> (256 - 132 - 24)) & 0xFFFFFF                            # next 24 bits
    return d, idx, idx24

def wots_pk_elements(seed, pre, key_idx, sig, msg16):
    d = digits_of(msg16)
    if sum(d) != DIGIT_SUM:
        return None
    pks = []
    for i in range(L):
        x = sig[i]
        for k in range(d[i], 3):
            x = tw(seed, pre(10, key_idx, i, k), x)
        pks.append(x)
    return pks

def xmss_layer(seed, layer, tree, key_idx, message16, counter, sig, path, trace=None):
    def pre(typ, w1, w2, w3):
        return adrs(layer, tree, typ, w1, w2, w3)
    msg = H(pre(13, key_idx, 0, 0) + seed + message16 + counter.to_bytes(4, 'big'))[:16]
    pks = wots_pk_elements(seed, pre, key_idx, sig, msg)
    if pks is None:
        return None
    leaf = tw(seed, pre(11, key_idx, 0, 0), b''.join(pks))
    node = leaf
    parent = key_idx
    bits = []
    for h in range(1, H_XMSS + 1):
        bit = parent & 1
        parent >>= 1
        bits.append(bit)
        node = tw(seed, pre(12, 0, h, parent), (path[h - 1] + node) if bit else (node + path[h - 1]))
    if trace is not None:
        trace.append(dict(layer=layer, tree=tree, key_idx=key_idx, msg=msg.hex(), leaf=leaf.hex(), root=node.hex(), bits=bits))
    return node

def fors_tree(seed, tree24, tree_no, leaf_idx, sk, path, trace=None):
    leaf = tw(seed, adrs(0, tree24, 6, tree_no, 0, leaf_idx), sk)
    node = leaf
    parent = leaf_idx
    bits = []
    for h in range(1, A + 1):
        bit = parent & 1
        parent >>= 1
        bits.append(bit)
        node = tw(seed, adrs(0, tree24, 7, tree_no, h, parent), (path[h - 1] + node) if bit else (node + path[h - 1]))
    if trace is not None:
        trace.append(dict(tree_no=tree_no, leaf_idx=leaf_idx, leaf=leaf.hex(), root=node.hex(), bits=bits))
    return node

def verify_stateless(message, seed, root, sf_root, r, fors, layers, trace=None):
    d, idx, idx24 = digest_indices(seed, root, message, r)
    if idx[5] != 0:
        return False, 'sixth index not zero'
    tr_fors = [] if trace is not None else None
    roots = [fors_tree(seed, idx24, t, idx[t], fors[t][0], fors[t][1], tr_fors) for t in range(K_TREES)]
    fors_pk = tw(seed, adrs(0, idx24, 8, 0, 0, 0), b''.join(roots))
    tr_x = [] if trace is not None else None
    msg16 = fors_pk
    key_idx = idx24 & 0xFFF
    tree = idx24 >> 12
    for layer in range(D_LAYERS):
        counter, sig, path = layers[layer]
        msg16 = xmss_layer(seed, layer, tree, key_idx, msg16, counter, sig, path, tr_x)
        if msg16 is None:
            return False, f'layer {layer} checksum'
        key_idx = tree
        tree >>= 12
    final = tw(seed, adrs(0, 0, 16, 0, 0, 0), sf_root + msg16)
    if trace is not None:
        trace.update(digest=d.hex(), idx=idx, idx24=idx24, fors=tr_fors, fors_pk=fors_pk.hex(), xmss=tr_x, sphincs_root=msg16.hex(), final=final.hex())
    return final == root, final.hex()

if __name__ == '__main__':
    key = None; n = 0; ok = 0
    for line in open(sys.argv[1]):
        rec = json.loads(line)
        if rec['kind'] == 'key':
            key = rec; continue
        if rec['kind'] != 'stateless':
            continue
        v = parse_vector(rec, key)
        res, _ = verify_stateless(**v)
        n += 1; ok += res
    print(f'reference stateless verifier: {ok}/{n} vectors accepted')
