---
layout: post
title: "Post-Quantum Cryptography Without the Math PhD"
date: 2026-08-24
categories: [security, cryptography, post-quantum]
tags: [cryptography, encryption, post-quantum]
math: true
author: 
description: "Under the hood of post-quantum encryption, without (almost) any Greek letters"
---
This article is also available on Medium: https://medium.com/@alfred.abston/post-quantum-cryptography-without-the-math-phd-185b288e3799

# Introduction

For decades, RSA and Diffie-Hellman have been the backbone of asymmetric cryptography. RSA lets you encrypt a message with someone's public key so that only their private key can decrypt it — its security rests on the presumed hardness of factoring large integers. Diffie-Hellman lets two parties derive a shared secret without ever transmitting it, relying on the hardness of the discrete logarithm problem. Elliptic Curve Cryptography (ECC) is essentially Diffie-Hellman transplanted into elliptic curve groups: the same mathematical idea but with much smaller keys for the same security level.

These systems have served us well. But in 1994, mathematician Peter Shor published a quantum algorithm that can both factor large integers *and* solve discrete logarithms in polynomial time. A sufficiently powerful quantum computer would render RSA, Diffie-Hellman, and all elliptic-curve variants obsolete.

The threat is not purely theoretical. Adversaries operating on long time horizons may already be recording encrypted traffic today, planning to decrypt it once quantum hardware matures — the so-called "harvest now, decrypt later" strategy. In response, NIST ran a multi-year post-quantum cryptography competition that concluded in 2024 with three new standards: FIPS 203 (ML-KEM, based on the Kyber algorithm) [[3, 4]](#references), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). ML-KEM is the designated post-quantum Key Encapsulation Mechanism.

This article is a **deep but accessible** walkthrough of how post-quantum key encapsulation actually works under the hood. I deliberately chose **FrodoKEM** as the entry point rather than ML-KEM: FrodoKEM is the simpler, more conservative cousin — it uses plain matrices over modular integers rather than the structured polynomial rings that make ML-KEM faster but harder to explain from first principles.

**What you need:** comfort with matrix multiplication and modular arithmetic. No academic-level cryptology or number field theory required.


# Key-Encapsulation Mechanism

Unlike Diffie-Hellman and ECDH — which are *key negotiation* protocols where both parties contribute randomness to a shared secret — a Key Encapsulation Mechanism (KEM) works differently: one party generates the key material, encrypts it using the other party's public parameters, and the receiving party decrypts it to recover the shared key.

The closest classical analog is ElGamal encryption. Let us construct a KEM using it to establish the pattern we will then replicate with lattices.

**Preconditions:** Alice and Bob have agreed on public cryptosystem parameters — a prime $p > 2^{2048}$ and a generator $g < p$. With these parameters, no one can practically solve $Y = g^x \bmod p$ for an unknown $x$ (the discrete logarithm problem).

**Bob** has a long-term key pair: private $q_B < p$ and public $Q_B := g^{q_B} \bmod p$.

**Alice** wants to establish a shared key with Bob:
1. Generates an ephemeral key pair: $q_A < p$, $\;Q_A := g^{q_A} \bmod p$.
2. Generates key material $m < p$ and encrypts it: $C := Q_B^{q_A} + m \bmod p$.
3. Derives the shared key as $\mathrm{KDF}(m \mid Q_B)$, where KDF (Key Derivation Function) is a standard cryptographic primitive — typically HKDF or SHAKE — that turns raw key material into a fixed-length symmetric key suitable for use in, say, AES.
4. Sends $(Q_A,\, C)$ to Bob.

**Bob** receives $(Q_A, C)$ and recovers the key material:

$$m' := C - Q_A^{q_B} \bmod p \;\equiv\; Q_B^{q_A} + m - Q_A^{q_B} \bmod p \;\equiv\; g^{q_A q_B} + m - g^{q_A q_B} \bmod p \;\equiv\; m$$

Bob then derives the same shared key. Notice the elegant symmetry: the shared Diffie-Hellman value $g^{q_A q_B}$ acts as a one-time mask that Alice adds to the key material and Bob subtracts.


# Key-Encapsulation Mechanism: FrodoKEM

I deliberately chose FrodoKEM instead of ML-KEM to avoid overcomplicating this post with "matrices over polynomials over cyclic rings" — we only need plain matrices and modular arithmetic. Hash functions, Gaussian sampling, and similar implementation details are omitted throughout: important for real-world security, but not needed to grasp the core idea.

The goal: reproduce something *structurally similar* to the ElGamal KEM above, but using a lattice instead of a group.

**Preconditions:** Alice and Bob have agreed on a public matrix $A_{k \times k}$. Each element comes from $\mathbb{Z}_Q$ — the ring of integers modulo $Q$ — meaning only two operations exist between elements: addition $a + b \bmod Q$ and multiplication $a \times b \bmod Q$.

**Bob** has a key pair:
- Private: $\mathbf{q}_B$ — a "small" secret column vector (coefficients much smaller than $Q$).
- Public: $\mathbf{Q}_B = A \cdot \mathbf{q}_B + \mathbf{e}$, where $\mathbf{e}$ is a small secret one-time error vector (need not be stored).

**Alice** generates an ephemeral key pair and encrypts the key material:
1. Ephemeral secret: $\mathbf{q}_A$ — a small secret column vector.
2. Ephemeral public: $\mathbf{Q}_A := A^T \cdot \mathbf{q}_A + \mathbf{e}_1$, where $\mathbf{e}_1$ is a small secret one-time error vector. ($A^T$ denotes the transpose of $A$.)
3. Key material: $\mathbf{m}$ — a vector where each element is either $0$ or $\lfloor Q/2 \rfloor$.
4. Ciphertext: $C := \mathbf{Q}_B^T \cdot \mathbf{q}_A + \mathbf{e}_2 + \mathbf{m}$, where $\mathbf{e}_2$ is a small error vector.
5. Derives the shared key as $\mathrm{KDF}(\mathbf{m} \mid \mathbf{Q}_B)$.
6. Sends $(\mathbf{Q}_A,\, C)$ to Bob.

**Bob** receives $(\mathbf{Q}_A, C)$ and recovers the key material:

$$\mathbf{m}' := C - \mathbf{q}_B^T \cdot \mathbf{Q}_A$$

Expanding step by step:

$$
\begin{aligned}
\mathbf{m}' &\equiv \mathbf{Q}_B^T \cdot \mathbf{q}_A + \mathbf{e}_2 + \mathbf{m} - \mathbf{q}_B^T \cdot (A^T \cdot \mathbf{q}_A + \mathbf{e}_1) \\
   &\equiv (A \cdot \mathbf{q}_B + \mathbf{e})^T \cdot \mathbf{q}_A + \mathbf{e}_2 + \mathbf{m} - \mathbf{q}_B^T \cdot A^T \cdot \mathbf{q}_A - \mathbf{q}_B^T \cdot \mathbf{e}_1 \\
   &\equiv \mathbf{q}_B^T \cdot A^T \cdot \mathbf{q}_A + \mathbf{e}^T \cdot \mathbf{q}_A + \mathbf{e}_2 + \mathbf{m} - \mathbf{q}_B^T \cdot A^T \cdot \mathbf{q}_A - \mathbf{q}_B^T \cdot \mathbf{e}_1 \\
   &\equiv \mathbf{m} + \underbrace{\mathbf{e}^T \cdot \mathbf{q}_A + \mathbf{e}_2 - \mathbf{q}_B^T \cdot \mathbf{e}_1}_{\text{small noise}}
\end{aligned}
$$

The $\mathbf{q}_B^T \cdot A^T \cdot \mathbf{q}_A$ terms cancel exactly, just as $g^{q_A q_B}$ cancelled in the ElGamal case. What remains is $\mathbf{m}$ plus a noise term. Because $\mathbf{e}$, $\mathbf{q}_A$, $\mathbf{e}_2$, $\mathbf{q}_B$, and $\mathbf{e}_1$ are all "small", every product in the noise term is small, and the coefficients of their sum remain much less than $Q/2$.

Since each element of $\mathbf{m}$ is either $0$ or $\lfloor Q/2 \rfloor$, Bob recovers $\mathbf{m}$ by rounding each element of $\mathbf{m}'$ to the nearest of those two values. He then derives the same shared key.

Looks remarkably similar to ElGamal, doesn't it?

That is enough for a working understanding of how FrodoKEM operates. If you'd like to go one level deeper and understand *why* it is secure — where the hardness actually comes from — read on.

# The Security Foundation: Learning With Errors

Every asymmetric scheme reduces to a hard computational problem. Here is the one underpinning FrodoKEM — and why it holds up against quantum computers. Despite the length of this section, there is no complex math ahead — just a few intuitive observations.

## The hardness hierarchy

RSA is a useful reference point for comparison:

- **Encryption** (plaintext → ciphertext): modular exponentiation — easy, polynomial time.
- **Decryption with the private key**: modular exponentiation — equally easy.
- **Decryption without the private key**: computing a modular $e$-th root without knowing the factors — believed to require sub-exponential time.
- **Recovering the private key from the public key**: factoring the modulus $n = p \cdot q$ — equally hard.

For FrodoKEM and ML-KEM, the analogous hard problem is called **Learning With Errors (LWE)** [[1]](#references).

## A toy example

Let $Q = 1021$. Public parameter: $A = 931$. Bob's secrets: $s = 7$, $e = 5$. His public key:

$$t = A \cdot s + e \bmod Q = 931 \cdot 7 + 5 \bmod 1021 = 396$$

Now Alice wants to send Bob a single secret bit $\mu \in \{0, 1\}$. She encodes it as $\hat\mu$: $0 \mapsto 0$, $\;1 \mapsto \lfloor Q/2 \rfloor = 510$.

She picks her own secrets $y = 11$, $e_1 = 6$, $e_2 = 3$, and computes her public part:

$$u = A \cdot y + e_1 \bmod Q = 931 \cdot 11 + 6 \bmod 1021 = 37$$

and encrypts:

$$v = t \cdot y + e_2 + \hat\mu \bmod Q = 396 \cdot 11 + 3 + \hat\mu \bmod 1021 = \begin{cases} 275 & \hat\mu = 0 \\ 785 & \hat\mu = 510 \end{cases}$$

To decrypt, Bob computes:

$$\mu' = v - u \cdot s \bmod Q = v - 37 \cdot 7 \bmod 1021 = \begin{cases} 16 & v = 275 \\ 526 & v = 785 \end{cases}$$

$16$ is close to $0$ and $526$ is close to $510$ — both within a small error — so Bob rounds back to the original bit.

## The three design tensions

There are three interacting constraints that shape the concrete parameters of any LWE-based scheme.

**1. Upper bound on "small" — correctness.** If the error bound $\eta$ is too large, the equation $t = A \cdot s + e \bmod Q$ has multiple valid $(s, e)$ solutions, making decryption ambiguous. More concretely, the accumulated noise term $\mathbf{e}^T \cdot \mathbf{q}_A + \mathbf{e}_2 - \mathbf{q}_B^T \cdot \mathbf{e}_1$ must stay well below $Q/4$ so that rounding recovers $\mathbf{m}$ correctly. Its magnitude is roughly bounded by $3\eta^2 k$, where $k$ is the matrix dimension and $\eta$ is the per-coefficient bound — so the condition is $3\eta^2 k \ll Q/4$. A larger error bound narrows the margin; a smaller one widens it.

**2. Lower bound on "small" — security.** If the error terms are zero, the system collapses to an ordinary linear equation $A \cdot s = t \bmod Q$, which Gaussian elimination solves in microseconds. Even with nonzero errors, if the noise range is too narrow, an adversary can exhaustively try all plausible error vectors and back out $s$. The LWE assumption requires noise large enough that no efficient algorithm can distinguish a pair $(A, t)$ from a uniformly random pair.

**3. Dimension and modulus — quantum resistance.** In a one-dimensional setting (scalar $A$, $s$, $e$), LWE reduces to a simple modular equation that lattice basis reduction — specifically the LLL algorithm, an efficient technique to find short vectors in a lattice — can solve efficiently. The key insight is that the complexity of such attacks grows exponentially with the lattice dimension. Working with large matrices (real FrodoKEM parameters use $k \geq 640$) and a modulus of at least $2^{15}$ makes the LWE problem intractable for both classical and quantum computers.


# Summary

FrodoKEM and ML-KEM are built on a single elegant idea: **Learning With Errors** [[1]](#references). Given a matrix $A$ and a vector $\mathbf{b} = A \cdot \mathbf{s} + \mathbf{e} \bmod Q$ with small noise $\mathbf{e}$, recovering $\mathbf{s}$ is believed to be computationally hard — even for a quantum computer. No known quantum algorithm provides a meaningful speedup over the best classical lattice algorithms.

FrodoKEM [[2]](#references) builds a full key-encapsulation scheme directly on plain LWE, using ordinary $k \times k$ matrices. It is conservative and well-understood, at the cost of larger key and ciphertext sizes (roughly 10–20 KB at the recommended security level).

**ML-KEM** (Kyber) [[3, 4]](#references) starts from the same LWE idea but replaces plain integer matrices with structured *module lattices* — matrices whose entries are themselves polynomials in the quotient ring $\mathbb{Z}_Q[x]/(x^n+1)$. This algebraic structure enables the Number Theoretic Transform (the finite-field analogue of the Fast Fourier Transform) to speed up matrix multiplication dramatically, shrinking public keys to around 1–1.5 KB. The tradeoff is mathematical complexity: understanding ML-KEM's security fully requires polynomial rings and a variant called Module-LWE (MLWE).

Both schemes are already being deployed. TLS 1.3 implementations are adding hybrid key exchange modes that combine classical and post-quantum algorithms, and major CDN and browser vendors have been running ML-KEM in production traffic since 2024.

## References

1. Regev, O. (2005). [On lattices, learning with errors, random linear codes, and cryptography](https://dl.acm.org/doi/10.1145/1060590.1060603). *STOC 2005*. The original LWE paper.
2. Bos, J. et al. (2021). [FrodoKEM: Learning With Errors Key Encapsulation — Specification](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf). *frodokem.org*. Full parameter sets and security analysis.
3. Avanzi, R. et al. (2021). [CRYSTALS-Kyber: Algorithm Specifications and Supporting Documentation](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf). *pq-crystals.org*. The round-3 NIST submission for what became ML-KEM.
4. NIST (2024). [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final). *csrc.nist.gov*. The official standard.
