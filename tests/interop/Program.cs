using System.Formats.Asn1;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

if (args.Length != 2 || (args[0] != "generate" && args[0] != "verify"))
    throw new ArgumentException("Usage: interop generate|verify DIRECTORY");

string[] names = ["MLDSA44-ECDSA-P256-SHA256", "MLDSA65-ECDSA-P256-SHA512",
    "MLDSA65-ECDSA-P384-SHA512", "MLDSA87-ECDSA-P384-SHA512"];
foreach (string name in names)
{
    string directory = Path.Combine(args[1], name);
    if (args[0] == "generate")
    {
        CompositeMLDsaAlgorithm algorithm = typeof(CompositeMLDsaAlgorithm)
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(p => p.PropertyType == typeof(CompositeMLDsaAlgorithm))
            .Select(p => (CompositeMLDsaAlgorithm)p.GetValue(null)!)
            .Single(a => a.Name == name);
        if (!CompositeMLDsa.IsAlgorithmSupported(algorithm))
            throw new PlatformNotSupportedException(name);
        using CompositeMLDsa key = CompositeMLDsa.GenerateKey(algorithm);
        Directory.CreateDirectory(directory);
        byte[] message = Encoding.UTF8.GetBytes("sys-cert-store standard OID interop: " + name);
        byte[] privateKey = key.ExportPkcs8PrivateKey();
        try { File.WriteAllBytes(Path.Combine(directory, "private.der"), privateKey); }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
        File.WriteAllBytes(Path.Combine(directory, "public.der"), key.ExportSubjectPublicKeyInfo());
        File.WriteAllBytes(Path.Combine(directory, "message.bin"), message);
        File.WriteAllBytes(Path.Combine(directory, "signature.bin"), key.SignData(message, []));
    }
    else
    {
        using CompositeMLDsa key = CompositeMLDsa.ImportSubjectPublicKeyInfo(File.ReadAllBytes(Path.Combine(directory, "public.der")));
        byte[] certificate = File.ReadAllBytes(Path.Combine(directory, "certificate.der"));
        var outer = new AsnReader(certificate, AsnEncodingRules.DER);
        var sequence = outer.ReadSequence();
        byte[] tbs = sequence.ReadEncodedValue().ToArray();
        sequence.ReadEncodedValue();
        byte[] signature = sequence.ReadBitString(out int unused);
        sequence.ThrowIfNotEmpty();
        outer.ThrowIfNotEmpty();
        if (unused != 0 || !key.VerifyData(tbs.AsSpan(), signature.AsSpan(), []))
            throw new CryptographicException("Provider certificate signature did not verify in .NET: " + name);
        foreach (int offset in new[] { 0, signature.Length - 1 })
        {
            signature[offset] ^= 1;
            if (key.VerifyData(tbs.AsSpan(), signature.AsSpan(), []))
                throw new CryptographicException("Tampered signature accepted");
            signature[offset] ^= 1;
        }
        File.Delete(Path.Combine(directory, "private.der"));
    }
    Console.WriteLine($"{args[0]}: {name}");
}
