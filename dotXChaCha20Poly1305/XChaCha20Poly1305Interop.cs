using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace nebulae.dotXChaCha20Poly1305;

internal static class XChaCha20Poly1305Interop
{
    static XChaCha20Poly1305Interop()
    {
        XChaCha20Poly1305Library.Init();
    }

    // int xchacha20poly1305_ietf_encrypt(
    //   const uint8_t key32[32],
    //   const uint8_t nonce24[24],
    //   const uint8_t* aad, size_t aad_len,
    //   const uint8_t* plaintext, size_t plaintext_len,
    //   uint8_t* out, size_t* out_len)
    [DllImport("xchacha20poly1305", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int xchacha20poly1305_ietf_encrypt(
        byte[] key32,
        byte[] nonce24,
        IntPtr aad, UIntPtr aad_len,
        IntPtr plaintext, UIntPtr plaintext_len,
        byte[] output, out UIntPtr out_len);

    // int xchacha20poly1305_ietf_decrypt(
    //   const uint8_t key32[32],
    //   const uint8_t nonce24[24],
    //   const uint8_t* aad, size_t aad_len,
    //   const uint8_t* ciphertext_and_tag, size_t ciphertext_and_tag_len,
    //   uint8_t* out, size_t* out_len)
    [DllImport("xchacha20poly1305", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int xchacha20poly1305_ietf_decrypt(
        byte[] key32,
        byte[] nonce24,
        IntPtr aad, UIntPtr aad_len,
        IntPtr ciphertextAndTag, UIntPtr ciphertextAndTagLen,
        byte[] output, out UIntPtr out_len);
}
