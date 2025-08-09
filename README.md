# dotXChaCha20Poly1305

A high-performance, minimal, cross-platform wrapper around BoringSSL's xchacha20 poly1305 encryption and decryption implementation (ietf draft-irtf-cfrg-xchacha-03).

The native backend is compiled directly from BoringSSL's xchacha20poly1305 and related modules - ensuring constant-time cryptographic operations and production-grade optimizations across Windows, Linux, and macOS.

Tests are included and available in the Github repo.

[![NuGet](https://img.shields.io/nuget/v/nebulae.dotXChaCha20Poly1305.svg)](https://www.nuget.org/packages/nebulae.dotXChaCha20Poly1305)

---

## Features

- **Cross-platform**: Works on Windows, Linux, and macOS (x64 & Apple Silicon).
- **High performance**: Optimized for speed, leveraging native SIMD-enabled code.
- **Easy to use**: Simple API for key exchange.
- **Secure**: Uses Google's BoringSSL implementation, which is widely trusted in the industry.
- **Minimal dependencies**: No external dependencies required (all are included), making it lightweight and easy to integrate.

---

## Requirements

- .NET 8.0 or later
- Windows x64, Linux x64, or macOS (x64 & Apple Silicon)

---

## Usage

```csharp

using nebulae.dotXChaCha20Poly1305;
using System.Security.Cryptography;

// 32?byte key (store/handle securely!)
byte[] key = RandomNumberGenerator.GetBytes(32);

// 24?byte nonce - MUST be unique per (key, message)
byte[] nonce = RandomNumberGenerator.GetBytes(24);

// Optional AAD (not encrypted, but authenticated)
byte[] aad = "header".GetBytesUtf8();

// Your plaintext
byte[] plaintext = "hello, xchacha".GetBytesUtf8();

// Encrypt returns ciphertext || 16?byte tag
byte[] ct = XChaCha20Poly1305.Encrypt(key, nonce, plaintext, aad);

// Decrypt returns original plaintext (throws on auth failure)
byte[] pt = XChaCha20Poly1305.Decrypt(key, nonce, ct, aad);

```

With Spans

```csharp

ReadOnlySpan<byte> keySpan   = key;
ReadOnlySpan<byte> nonceSpan = nonce;
ReadOnlySpan<byte> aadSpan   = aad;
ReadOnlySpan<byte> ptSpan    = plaintext;

byte[] ct2 = XChaCha20Poly1305.Encrypt(keySpan, nonceSpan, ptSpan, aadSpan);
byte[] pt2 = XChaCha20Poly1305.Decrypt(keySpan, nonceSpan, ct2, aadSpan);

```

API

```csharp

public static class XChaCha20Poly1305
{
    // Encrypt: returns ciphertext || 16-byte tag
    public static byte[] Encrypt(
        ReadOnlySpan<byte> key32,
        ReadOnlySpan<byte> nonce24,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad = default);

    // Decrypt: returns plaintext; throws CryptographicException on failure
    public static byte[] Decrypt(
        ReadOnlySpan<byte> key32,
        ReadOnlySpan<byte> nonce24,
        ReadOnlySpan<byte> ciphertextWithTag,
        ReadOnlySpan<byte> aad = default);
}

```

---

## Installation

You can install the package via NuGet:

```bash

$ dotnet add package nebulae.dotXChaCha20Poly1305

```

Or via git:

```bash

$ git clone https://github.com/nebulaeonline/dotXChaCha20Poly1305.git
$ cd dotXChaCha20Poly1305
$ dotnet build

```

---

## License

MIT

## Roadmap

Unless there are vulnerabilities found, there are no plans to add any new features.