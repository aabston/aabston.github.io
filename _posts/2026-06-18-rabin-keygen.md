---
layout: post
title: "Lightweight Asymmetric Encryption for C2 Implants: A Red Teamer's Guide from XOR to Rabin"
date: 2026-06-18
categories: [security, cryptography, redteaming]
tags: [cryptography, red-team, encryption]
math: true
author: 
description: "A practical walkthrough of encryption choices for red team implants — from XOR and AES-CTR to Rabin key encapsulation — with a self-contained C implementation and no external dependencies."
---

> **Disclaimer:** This article is for security research, authorized penetration testing, and educational purposes only. Don't use this against systems you don't own or have explicit written authorization to test. No ready-to-use malware or evasion techniques will be provided.

The post is also mirrored to [medium](https://medium.com/@alfred.abston/lightweight-asymmetric-encryption-for-c2-implants-a-red-teamers-guide-from-xor-to-rabin-42e9b6b275d6?source=friends_link&sk=a8b1132678909ff0f00f5b8ff4f8b62b)


# 1. Objectives

How often do you need encryption during a pentest or red teaming engagement? Not long ago a simple reverse shell or Meterpreter session was enough to slip through undetected. Those days are largely gone — even Windows Defender now kills executables with obvious malicious patterns, so you need to hide them at a minimum. On top of that, when you exfiltrate personal data or harvest credentials as a legal red teamer, you have an obligation to protect that data from disclosure to unauthorized parties — including SOC engineers.

That's why every serious C2 implant needs a crypto pipeline. It should address:
- Preserving exfiltrated/stolen data from disclosure to third parties.
- Hiding suspicious payload signatures from AV/EDR.
- Code obfuscation.
- Defeating network-based detection (well-encrypted traffic looks like noise).

The application also imposes hard constraints:
- **No crypto API calls** — calling a Windows crypto API is a definite red flag for a defender monitoring API usage.
- **Tiny footprint** — shellcode is often size-constrained; every byte counts.
- **No external dependencies** — the implant must be entirely self-contained.

# 2. Naive approaches: XOR (Caesar, Vigenère)

The simplest and most common approach is bytewise XOR with a constant "secret" byte (Caesar cipher) or byte sequence (Vigenère cipher):

```c
void xor_encrypt(uint8_t *data, size_t len, const uint8_t *key, size_t klen) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= key[i % klen];
}
```

Despite its simplicity and partial invisibility to basic AV/EDR static analysis, this approach has serious disadvantages:
- Well-known code patterns — easily detectable with YARA rules.
- Extremely weak security — the "encrypted" data can be recovered without knowing the key.
- The statistical properties of XOR'd data are far from random, but also don't match regular code patterns like machine code or printable strings. That distinctive fingerprint attracts automated scanners.

# 3. Symmetric encryption

The natural upgrade is to use a cryptographically strong algorithm: AES, RC4, ChaCha20, ChaCha20-Poly1305, etc. You have several implementation strategies:

- **Call a Windows/Linux API or library** (e.g., OpenSSL). Advantages: minimal code, easy to use. Disadvantage: crypto API calls are a strong marker of suspicious activity and easy to hook.
- **Reimplement the algorithm inline.** Very common in implants — it removes recognizable IAT names from the binary (resistant to static analysis) and avoids system-level function hooking. Still detectable, though: algorithms like AES carry well-known byte constants and S-boxes that YARA rules can match:

```yara
rule AES_SBox {
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        $sbox
}
```

- **Harden further:** replace algorithm constants (reducing signatures), switch to ARX ciphers (Addition/Rotation/XOR only — no heavy constants or S-boxes), and obscure rotation operations by replacing `t << 5` with `t * 32` with compiler optimizations disabled (rotation inside a tight loop is a crypto fingerprint). This reduces the risk of automated signature detection with only a marginal impact on theoretical security — acceptable for red teaming.
- **Write a custom cipher.** May raise the cost of manual analysis, but is generally unreliable from a security standpoint, requires deep cryptographic knowledge, and becomes an Indicator of Compromise if reused across engagements.

> **Note:** If you use a block cipher like AES, run it in a stream mode. [Counter (CTR) mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) is a good default — it is simple and requires no padding. Avoid ECB (Electronic Codebook) mode, which is trivially distinguishable.

# 4. Asymmetric encryption

Symmetric ciphers provide strong security, but only if the secret key is truly random, high-entropy, and — most critically — unknown to the analyst. Hardcoding a symmetric key in an implant is a serious risk: anyone who extracts the binary has the key and can decrypt all captured data from every instance of that implant.

In many red teaming scenarios you primarily want to evade EDR. But there are cases where you genuinely need asymmetric key establishment:
- **C2 communication:** transmitted sensitive data must not be accessible to SOC engineers or admins who are not authorized to view it.
- **Credential harvesting:** captured data must be protected in transit for the same reason.
- **Multi-target campaigns:** a hardcoded symmetric key extracted from one implant compromises all other instances. Asymmetric encryption eliminates this link.

The high-level flow for establishing a secure implant-to-C2 channel looks like this:

```
Implant                                   C2 server
  |                                           |
  | <-- n (Hardcoded public key       ) ---   | (baked in at build time)
  |                                           |
  | generate symkey                           |
  | ciphertext = asym _encrypt(symkey, n)     |
  |------- ciphertext ----------------------->|
  |                                           | symkey = asym_decrypt(ciphertext, p, q)
  |<========= AES/ChaCha20 encrypted data ===>|
```

The implant generates a random symmetric key, encrypts it with the hardcoded public key, and sends only the ciphertext to the C2. Only the C2 — which holds the private factors $p$ and $q$ — can recover the symmetric key. Even if an analyst fully extracts the implant binary, they see only the public key $n$, which is useless for decryption.

The question is: which asymmetric algorithm to use?

## 4.1 ECC (secp192r1, secp256r1, etc.)

The most popular algorithm family: strong security, high performance, and compact key sizes. The downsides for implant use are significant — reimplementing ECC from scratch produces a large binary, and curve parameters and constants are highly detectable by signature scanners.

## 4.2 RSA and Diffie-Hellman

Although RSA and Diffie-Hellman are based on different computational problems, they share a critical implementation challenge: both require a Big Integer library.

As a representative example, here is the Diffie-Hellman key exchange:

**Diffie-Hellman**

Parameters:
- Private: $x < p$ — randomly generated integer with the same bit size as $p$.
- Public: $p$ — a randomly generated prime modulus (recommended minimum: 2048 bits; absolutely not less than 1024 bits for red teaming); $g < p$ — a group generator; $X := g^x \bmod p$ — the long-term public key.

Key establishment on the implant side:
1. Generate an unpredictable random ephemeral private key: $y < p$.
2. Calculate the ephemeral public key: $Y := g^y \bmod p$.
3. Calculate the shared secret: $s := X^y \bmod p$.
4. Encrypt and transmit the tuple $Y \| \mathrm{Enc}_s(\mathrm{data})$.

On the C2 side the same shared secret can be derived: $s' := Y^x \bmod p$. They are equal because:

$$s = X^y \bmod p = (g^x)^y \bmod p = g^{xy} \bmod p = Y^x \bmod p = s'$$

> I deliberately omit strict security requirements — "strong" prime, when $\frac{p-1}{2}$ is prime as well, CSPRNG, etc. — because in red teaming we want a compact, hidden implementation with adequate security, not a FIPS-certified one.

As you can see, the implant needs at minimum a random number generator and big-integer modular exponentiation — which in turn requires big-integer addition, subtraction, multiplication, and modulo reduction. RSA has essentially the same footprint. Optimizations like Karatsuba multiplication or Montgomery reduction can help, but they increase code size further (trust me, I tried).

## 4.3 Rabin encryption

The [Rabin cryptosystem](https://en.wikipedia.org/wiki/Rabin_cryptosystem) is less well-known than RSA but has a notable theoretical property: breaking it is provably equivalent to factoring the public modulus. RSA's equivalence to factoring has never been proven. So Rabin is theoretically stronger than RSA — though for red teaming this distinction barely matters.

What does matter: **Rabin encryption requires only modular squaring** ($c = a^2 \bmod n$), not general modular exponentiation. There is no need for an arbitrary `a × b` big-integer multiply — just `a × a`. That makes the encryption side dramatically simpler than RSA or Diffie-Hellman.

For key encapsulation with a hardcoded public key, the entire encryption fits in ~50 lines of pure C:

```c
static void rabin_encrypt(const unsigned a[32], unsigned result[32])
{
    // rabin public key
    static const unsigned n[32] = {
        0xed4e3091, 0x24270282, 0xac5a8f64, 0xaeb08a2e, 0x097d0d82, 0xcef4848a, 0x8a68d47b, 0xe59e9e68,
        0xf4c9eb25, 0xc5640d5c, 0x49fb8940, 0x19272dc3, 0x59ed9fda, 0xbf701f48, 0x8826b545, 0x868b0515,
        0xb61740cf, 0x878f556e, 0x3f3e37fc, 0x55d7f10d, 0x7a94b0db, 0xb7202e8a, 0x52b97f6b, 0xe9af0929,
        0xfd69f13d, 0x97343f92, 0x29c6e89b, 0x410c3af4, 0xec411218, 0x37fb0fcd, 0x9d8b3941, 0xb784d1aa
    };

    //squaring a*a
    unsigned sq[2*32], div[2*32];
    int msb_r = -1, msb_d = -1, b;
    for (int i = 0; i < 2*32; i++) sq[i] = 0;
    for (int i = 0; i < 32; i++) {
        unsigned long long c = 0;
        for (int j = 0; j < 32; j++) {
            unsigned long long p = (unsigned long long)a[i] * a[j] + sq[i+j] + c;
            sq[i+j] = (unsigned)p;
            c = p >> 32;
        }
        sq[i+32] = (unsigned)c;
    }

    //modulo a*a % n
    for (int i = 2*32-1; i >= 0; i--) {
        div[i] = i < 32 ? n[i] : 0;
        if (sq[i] && msb_r < 0) { b = 31; while (!(sq[i] & (1u<<b))) b--; msb_r = i*32+b; }
        if (i < 32 && div[i] && msb_d < 0) { b = 31; while (!(div[i] & (1u<<b))) b--; msb_d = i*32+b; }
    }
    if (msb_d < 0) return;
    int shift = msb_r - msb_d;
    for (int i = 0; i < shift; i++) {
        for (int k = 2*32-1; k > 0; k--) div[k] = (div[k] << 1) | (div[k-1] >> 31);
        div[0] <<= 1;
    }
    for (int i = 0; i <= shift; i++) {
        int c = 0;
        for (int m = 2*32-1; m >= 0 && !c; m--) c = sq[m] > div[m] ? 1 : sq[m] < div[m] ? -1 : 0;
        if (c >= 0) {
            unsigned long long bw = 0;
            for (int s = 0; s < 2*32; s++) {
                unsigned long long d = (unsigned long long)sq[s] - (unsigned long long)div[s] - bw;
                sq[s] = (unsigned)d;
                bw = d >> 32 ? 1 : 0;
            }
        }
        for (int k = 0; k < 2*32-1; k++) div[k] = (div[k] >> 1) | (div[k+1] << 31);
        div[2*32-1] >>= 1;
    }
    for (int i = 0; i < 32; i++) result[i] = sq[i];
}
```

This function computes $a^2 \bmod n$ — that's exactly the Rabin encryption.

A few critical considerations:

- **Plaintext size:** the plaintext $a$ must satisfy $a > \sqrt{n}$. If $a < \sqrt{n}$, then $a^2 < n$ and the modulo is trivial — decryption reduces to an integer square root, which is polynomial time. In practice, padding `a` to the full key size guarantees this constraint is met.
- **Symmetric key generation** is outside the scope of this article. By default `generate_symkey` reads entropy from `/dev/urandom`; substitute a platform-appropriate source if that's unavailable on your target.
- **Root disambiguation:** Rabin decryption yields 4 square root candidates. To identify the correct one, `symkey[0]` is set to `RABIN_MAGIC` (the least-significant 32-bit word of $n$) before encryption. The server picks the root whose first four bytes match this value.

### Rabin keygen implementation

The companion Python toolkit [`rabin.py`](https://github.com/aabston/rabin-keygen) handles key generation, server-side decryption, and stamping the public key into the C template.

The overall usage flow — from key generation through deployment to runtime decryption:

```
[Operator — build time]
    │
    ├─ python3 rabin.py --keygen 1024 ──────────────→ key.json  (p, q, n)
    │                                                      │
    ├─ python3 rabin.py --ccode key.json                   │
    │       └──→ rabin-keygen.impl.c                       │
    │               └──→ gcc ──→ implant binary            │
    │                            (n hardcoded inside)      │
    │                                                      │ (kept secret on C2)
    │                                                      │
[Implant — target machine]                         [C2 server]
    │                                                      │
    │  generate_symkey()     → symkey (RABIN_MAGIC prefix) │
    │  rabin_encrypt(symkey) → enckey                      │
    │──────────────────── enckey (ciphertext) ────────────→│
    │                                                      │ key_decrypt(p, q, enckey)
    │                                                      └──→ symkey (hex)
```

It requires one dependency:

```sh
pip install pycryptodome
```

#### Key generation

```sh
python3 rabin.py --keygen 1024 > key.json
```

Outputs a JSON file:

```json
{
  "p": "<base64>",
  "q": "<base64>",
  "n": "<base64>"
}
```

`p` and `q` are the private factors; `n` is the public modulus. Default key size is 1024 bits; 2048 bits is recommended for longer-lived operations.

#### Stamping the C template

```sh
python3 rabin.py --ccode key.json   # writes rabin-keygen.impl.c
```

The script reads `rabin-keygen.c.template` and substitutes three placeholders:

| Placeholder | Value |
|---|---|
| `RABIN_MAGIC` | `n & 0xFFFFFFFF` as a hex literal |
| `WORDS` | number of 32-bit words in `n` |
| `RABIN_PUBKEY` | little-endian `unsigned` initializer list |

The output `rabin-keygen.impl.c` is ready to compile with no further changes.

#### Client (implant) side

```c
unsigned symkey[WORDS], enckey[WORDS];
generate_symkey(symkey);   // symkey[0] is pre-set to RABIN_MAGIC
rabin_encrypt(symkey, enckey);
// transmit enckey to C2
```

`generate_symkey` fills the buffer from `/dev/urandom` and sets `symkey[0] = RABIN_MAGIC`. Replace the entropy source with whatever is appropriate for your target platform. Copy `rabin_encrypt` and `generate_symkey` directly into your project — no headers or libraries needed. Roughly **60 lines of pure C** for practically secure asymmetric encryption at 1024 bits and above.

#### Server (C2) side

**Manual decryption:**
```sh
echo <enckey_hex> | python3 rabin.py --decrypt key.json
```

**Programmatic (Python):**
```python
from rabin import key_decrypt
symkey = key_decrypt(p_b64, q_b64, enckey_hex).hex()
```

#### Full round-trip

```sh
# 1. Generate key pair
python3 rabin.py --keygen 1024 > key.json

# 2. Stamp public key into C template
python3 rabin.py --ccode key.json        # → rabin-keygen.impl.c

# 3. Compile
gcc -o rabin-keygen rabin-keygen.impl.c

# 4. Generate and encrypt a symmetric key on the implant side
./rabin-keygen
# line 1: plaintext symmetric key (hex)
# line 2: Rabin-encrypted key (hex)

# 5. Decrypt on the server side
echo <encrypted_key> | python3 rabin.py --decrypt key.json
# → plaintext symmetric key (hex)
```

# 5. Conclusion

Modern defensive tooling has raised the bar significantly — a bare reverse shell or Meterpreter session gets flagged almost immediately, and hardcoded keys extracted from implants can blow an entire campaign. A layered crypto pipeline is no longer optional; it is a baseline requirement for any serious red teaming operation.

The progression laid out in this article follows the attacker-defender arms race:

- **XOR / Vigenère:** trivially bypassed by YARA rules and statistical analysis.
- **Symmetric ciphers (AES, ChaCha20):** cryptographically strong, but hardcoded keys are a single point of failure and algorithm constants remain detectable.
- **Asymmetric key encapsulation (Rabin):** eliminates the hardcoded-key risk entirely, compresses to ~60 lines of pure C, and introduces no detectable constants.

Rabin's appeal for implants is the combination of compactness, self-containedness, and adequate security. Squaring is the only complex operation required — no full big-integer library, no heavy constants, no API calls. Decryption lives entirely on the C2 server and never touches the implant binary. The public key is just an array of `unsigned` words that blends naturally into surrounding data.

The complete toolkit — key generation, C template stamping, and Python-side decryption — is available at [https://github.com/aabston/rabin-keygen](https://github.com/aabston/rabin-keygen).

As always: use this only against systems you own or have explicit written authorization to test.

# 6. References

1. [Rabin cryptosystem — Wikipedia](https://en.wikipedia.org/wiki/Rabin_cryptosystem)
2. [Key Encapsulation Mechanism — Wikipedia](https://en.wikipedia.org/wiki/Key_encapsulation_mechanism)
3. [Diffie–Hellman key exchange — Wikipedia](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
4. [Block cipher modes of operation: CTR — Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))
5. [ChaCha20-Poly1305 — RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
6. [Advanced Encryption Standard — NIST FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final)
7. [YARA documentation](https://yara.readthedocs.io/)
8. [Rabin.py PoC — GitHub](https://github.com/aabston/rabin-keygen)
