using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace nebulae.dotXChaCha20Poly1305;

public static class XChaCha20Poly1305
{
    private const int KeyLen = 32;
    private const int NonceLen = 24;
    private const int TagLen = 16;

    public static byte[] Encrypt(
        ReadOnlySpan<byte> key32,
        ReadOnlySpan<byte> nonce24,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad = default)
    {
        if (key32.Length != KeyLen) throw new ArgumentException("Key must be 32 bytes", nameof(key32));
        if (nonce24.Length != NonceLen) throw new ArgumentException("Nonce must be 24 bytes", nameof(nonce24));

        var key = key32.ToArray();
        var nonce = nonce24.ToArray();

        var output = new byte[plaintext.Length + TagLen];

        unsafe
        {
            fixed (byte* pAad = aad)
            fixed (byte* pPt = plaintext)
            {
                var ok = XChaCha20Poly1305Interop.xchacha20poly1305_ietf_encrypt(
                    key, nonce,
                    (IntPtr)pAad, (UIntPtr)aad.Length,
                    (IntPtr)pPt, (UIntPtr)plaintext.Length,
                    output, out var outLen);

                if (ok != 1)
                    throw new CryptographicException("XChaCha20-Poly1305 encryption failed");

                // outLen should equal output.Length; trim if the native impl ever returns less
                if ((ulong)outLen != (ulong)output.Length)
                    Array.Resize(ref output, (int)outLen);
            }
        }

        return output;
    }

    public static byte[] Decrypt(
        ReadOnlySpan<byte> key32,
        ReadOnlySpan<byte> nonce24,
        ReadOnlySpan<byte> ciphertextWithTag,
        ReadOnlySpan<byte> aad = default)
    {
        if (key32.Length != KeyLen) throw new ArgumentException("Key must be 32 bytes", nameof(key32));
        if (nonce24.Length != NonceLen) throw new ArgumentException("Nonce must be 24 bytes", nameof(nonce24));
        if (ciphertextWithTag.Length < TagLen) throw new ArgumentException("Ciphertext too short", nameof(ciphertextWithTag));

        var key = key32.ToArray();
        var nonce = nonce24.ToArray();

        var output = new byte[ciphertextWithTag.Length - TagLen]; // plaintext size

        unsafe
        {
            fixed (byte* pAad = aad)
            fixed (byte* pCt = ciphertextWithTag)
            {
                var ok = XChaCha20Poly1305Interop.xchacha20poly1305_ietf_decrypt(
                    key, nonce,
                    (IntPtr)pAad, (UIntPtr)aad.Length,
                    (IntPtr)pCt, (UIntPtr)ciphertextWithTag.Length,
                    output, out var outLen);

                if (ok != 1)
                    throw new CryptographicException("XChaCha20-Poly1305 authentication failed");

                if ((ulong)outLen != (ulong)output.Length)
                    Array.Resize(ref output, (int)outLen);
            }
        }

        return output;
    }
}
