using nebulae.dotXChaCha20Poly1305;
using System.Security.Cryptography;
using System.Text;

namespace dotXChaCha20Poly1305Tests;

public class dotXChaCha20Poly1305Tests
{
    private static byte[] Hex(string s) =>
        Enumerable.Range(0, s.Length / 2)
            .Select(i => Convert.ToByte(s.Substring(2 * i, 2), 16))
            .ToArray();

    private static byte[] Rnd(int len, int seed)
    {
        var r = new Random(seed);
        var b = new byte[len];
        r.NextBytes(b);
        return b;
    }

    private static byte[] Clone(byte[] a)
    {
        var c = new byte[a.Length];
        Buffer.BlockCopy(a, 0, c, 0, a.Length);
        return c;
    }

    private static void FlipOneBit(byte[] a, int index, int bit = 0)
    {
        a[index] ^= (byte)(1 << bit);
    }

    private static byte[] Key => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static byte[] Nonce => Enumerable.Range(64, 24).Select(i => (byte)i).ToArray();

    [Fact]
    public void Encrypt_Vector_From_Draft()
    {
        // draft-irtf-cfrg-xchacha-03 A.1 AEAD_XCHACHA20_POLY1305
        var key = Hex("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
        var nonce = Hex("404142434445464748494A4B4C4D4E4F5051525354555657");
        var aad = Hex("50515253C0C1C2C3C4C5C6C7");

        var ptStr = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        var pt = Encoding.ASCII.GetBytes(ptStr);

        var expectedCt = Hex(
            "BD6D179D3E83D43B9576579493C0E939" +
            "572A1700252BFACC BED2902C21396CBB".Replace(" ", "") +
            "731C7F1B0B4AA6440BF3A82F4EDA7E39" +
            "AE64C6708C54C216CB96B72E1213B452" +
            "2F8C9BA40DB5D945B11B69B982C1BB9E" +
            "3F3FAC2BC369488F76B2383565D3FFF9" +
            "21F9664C97637DA9768812F615C68B13" +
            "B52E"
        );

        var expectedTag = Hex("C0875924C1C7987947DEAFD8780ACF49");

        var ctAndTag = XChaCha20Poly1305.Encrypt(key, nonce, pt, aad);
        Assert.Equal(expectedCt.Concat(expectedTag).ToArray(), ctAndTag);
    }

    [Fact]
    public void Decrypt_Vector_From_Draft()
    {
        var key = Hex("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
        var nonce = Hex("404142434445464748494A4B4C4D4E4F5051525354555657");
        var aad = Hex("50515253C0C1C2C3C4C5C6C7");

        var ptStr = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        var expectedPt = Encoding.ASCII.GetBytes(ptStr);

        var ct = Hex(
            "BD6D179D3E83D43B9576579493C0E939" +
            "572A1700252BFACC BED2902C21396CBB".Replace(" ", "") +
            "731C7F1B0B4AA6440BF3A82F4EDA7E39" +
            "AE64C6708C54C216CB96B72E1213B452" +
            "2F8C9BA40DB5D945B11B69B982C1BB9E" +
            "3F3FAC2BC369488F76B2383565D3FFF9" +
            "21F9664C97637DA9768812F615C68B13" +
            "B52E"
        );
        var tag = Hex("C0875924C1C7987947DEAFD8780ACF49");

        var ctAndTag = ct.Concat(tag).ToArray();
        var pt = XChaCha20Poly1305.Decrypt(key, nonce, ctAndTag, aad);
        Assert.Equal(expectedPt, pt);
    }

    [Fact]
    public void Decrypt_Fails_On_Tamper()
    {
        var key = Hex("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
        var nonce = Hex("404142434445464748494A4B4C4D4E4F5051525354555657");
        var aad = Hex("50515253C0C1C2C3C4C5C6C7");

        var ct = Hex(
            "BD6D179D3E83D43B9576579493C0E939" +
            "572A1700252BFACC BED2902C21396CBB".Replace(" ", "") +
            "731C7F1B0B4AA6440BF3A82F4EDA7E39" +
            "AE64C6708C54C216CB96B72E1213B452" +
            "2F8C9BA40DB5D945B11B69B982C1BB9E" +
            "3F3FAC2BC369488F76B2383565D3FFF9" +
            "21F9664C97637DA9768812F615C68B13" +
            "B52E"
        );
        var tag = Hex("C0875924C1C7987947DEAFD8780ACF49");

        var ctAndTag = ct.Concat(tag).ToArray();
        ctAndTag[^1] ^= 0x01; // flip one bit in tag

        Assert.Throws<CryptographicException>(() =>
            XChaCha20Poly1305.Decrypt(key, nonce, ctAndTag, aad)
        );
    }

    [Fact]
    public void Empty_Plaintext_And_Aad_Roundtrip()
    {
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
        Assert.Equal(16, ct.Length);
        var pt = XChaCha20Poly1305.Decrypt(Key, Nonce, ct, ReadOnlySpan<byte>.Empty);
        Assert.Empty(pt);
    }

    [Fact]
    public void Empty_Plaintext_With_AAD_Roundtrip()
    {
        var aad = Encoding.ASCII.GetBytes("AAD");
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, ReadOnlySpan<byte>.Empty, aad);
        Assert.Equal(16, ct.Length);
        var pt = XChaCha20Poly1305.Decrypt(Key, Nonce, ct, aad);
        Assert.Empty(pt);
    }

    [Fact]
    public void NonEmpty_Plaintext_NoAAD_Roundtrip()
    {
        var pt0 = Encoding.ASCII.GetBytes("hello");
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt0, ReadOnlySpan<byte>.Empty);
        Assert.Equal(pt0.Length + 16, ct.Length);
        var pt = XChaCha20Poly1305.Decrypt(Key, Nonce, ct, ReadOnlySpan<byte>.Empty);
        Assert.Equal(pt0, pt);
    }

    // 2) Size edges for PT and AAD
    [Theory]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(1024)]
    public void Edge_Sizes_Roundtrip(int len)
    {
        var pt0 = Rnd(len, 12345);
        var aad = Rnd(13, 54321);
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt0, aad);
        Assert.Equal(len + 16, ct.Length);
        var pt = XChaCha20Poly1305.Decrypt(Key, Nonce, ct, aad);
        Assert.Equal(pt0, pt);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(13)]
    [InlineData(16)]
    [InlineData(20)]
    public void Edge_AAD_Sizes_Roundtrip(int aadLen)
    {
        var pt0 = Rnd(97, 999);
        var aad = Rnd(aadLen, 111);
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt0, aad);
        var pt = XChaCha20Poly1305.Decrypt(Key, Nonce, ct, aad);
        Assert.Equal(pt0, pt);
    }

    [Fact]
    public void Deterministic_For_Same_Inputs()
    {
        var pt = Rnd(200, 7);
        var aad = Rnd(31, 8);
        var ct1 = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, aad);
        var ct2 = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, aad);
        Assert.Equal(ct1, ct2);
        Assert.Equal(pt.Length + 16, ct1.Length);
        var dec = XChaCha20Poly1305.Decrypt(Key, Nonce, ct1, aad);
        Assert.Equal(pt, dec);
    }

    [Fact]
    public void Tamper_Ciphertext_Fails()
    {
        var pt = Rnd(128, 42);
        var aad = Rnd(9, 24);
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, aad);
        var bad = Clone(ct);
        
        // flip a byte in the ciphertext part (avoid the tag region)
        FlipOneBit(bad, 0);
        Assert.Throws<CryptographicException>(() => XChaCha20Poly1305.Decrypt(Key, Nonce, bad, aad));
    }

    [Fact]
    public void Tamper_Tag_Fails()
    {
        var pt = Rnd(64, 55);
        var aad = Rnd(5, 77);
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, aad);
        var bad = Clone(ct);
        
        FlipOneBit(bad, bad.Length - 1);
        Assert.Throws<CryptographicException>(() => XChaCha20Poly1305.Decrypt(Key, Nonce, bad, aad));
    }

    [Fact]
    public void Tamper_AAD_Fails()
    {
        var pt = Rnd(64, 1);
        var aad = Rnd(12, 2);
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, aad);
        var aadBad = Clone(aad);

        FlipOneBit(aadBad, 0);
        Assert.Throws<CryptographicException>(() => XChaCha20Poly1305.Decrypt(Key, Nonce, ct, aadBad));
    }

    [Fact]
    public void Truncated_Tag_Fails()
    {
        var pt = Rnd(10, 3);
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, ReadOnlySpan<byte>.Empty);
        var truncated = new byte[ct.Length - 1];

        Buffer.BlockCopy(ct, 0, truncated, 0, truncated.Length);
        Assert.Throws<CryptographicException>(() => XChaCha20Poly1305.Decrypt(Key, Nonce, truncated, ReadOnlySpan<byte>.Empty));
    }

    // 5) Wrong key / nonce
    [Fact]
    public void Wrong_Key_Fails()
    {
        var pt = Rnd(33, 4);
        var aad = Rnd(7, 5);
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, aad);
        var wrongKey = Clone(Key);

        wrongKey[0] ^= 0x80;
        Assert.Throws<CryptographicException>(() => XChaCha20Poly1305.Decrypt(wrongKey, Nonce, ct, aad));
    }

    [Fact]
    public void Wrong_Nonce_Fails()
    {
        var pt = Rnd(33, 6);
        var aad = Rnd(7, 7);
        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, aad);
        var wrongNonce = Clone(Nonce);

        wrongNonce[0] ^= 0x01;
        Assert.Throws<CryptographicException>(() => XChaCha20Poly1305.Decrypt(Key, wrongNonce, ct, aad));
    }

    [Fact]
    public void Default_AAD_Equals_Empty_AAD()
    {
        var pt = Rnd(50, 12);
        var ct1 = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, default); // default(ReadOnlySpan<byte>)
        var ct2 = XChaCha20Poly1305.Encrypt(Key, Nonce, pt, ReadOnlySpan<byte>.Empty);
        Assert.Equal(ct1, ct2);

        var d1 = XChaCha20Poly1305.Decrypt(Key, Nonce, ct1, default);
        var d2 = XChaCha20Poly1305.Decrypt(Key, Nonce, ct1, ReadOnlySpan<byte>.Empty);
        Assert.Equal(d1, d2);
        Assert.Equal(pt, d1);
    }

    [Fact]
    public void Invalid_Key_Or_Nonce_Lengths_Throw()
    {
        var pt = Rnd(8, 9);
        var badKey = new byte[31];
        var badNonce = new byte[23];

        Assert.Throws<ArgumentException>(() => XChaCha20Poly1305.Encrypt(badKey, Nonce, pt));
        Assert.Throws<ArgumentException>(() => XChaCha20Poly1305.Encrypt(Key, badNonce, pt));

        var ct = XChaCha20Poly1305.Encrypt(Key, Nonce, pt);
        Assert.Throws<ArgumentException>(() => XChaCha20Poly1305.Decrypt(badKey, Nonce, ct));
        Assert.Throws<ArgumentException>(() => XChaCha20Poly1305.Decrypt(Key, badNonce, ct));
    }

    [Fact]
    public async Task Parallel_Encrypt_Decrypt_Roundtrips()
    {
        const int N = 32;
        var pt = Rnd(256, 101);
        var aad = Rnd(32, 202);

        var tasks = Enumerable.Range(0, N).Select(i => Task.Run(() =>
        {
            // unique nonce per task
            var nonce = Clone(Nonce);
            nonce[^1] = (byte)i;

            var ct = XChaCha20Poly1305.Encrypt(Key, nonce, pt, aad);
            var dec = XChaCha20Poly1305.Decrypt(Key, nonce, ct, aad);

            Assert.Equal(pt.Length + 16, ct.Length);
            Assert.Equal(pt, dec);
            return ct;
        })).ToArray();

        var results = await Task.WhenAll(tasks);

        // ensure distinct nonces to ciphertexts should (overwhelmingly) differ
        Assert.True(results.Distinct().Count() > N / 2);
    }
}