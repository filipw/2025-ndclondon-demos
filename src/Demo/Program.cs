using System;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Spectre.Console;

var demo = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("Choose the [green]demo[/] to run?")
        .AddChoices(new[]
        {
            "ML-KEM", "ML-DSA"
        }));

switch (demo)
{
    case "ML-KEM":
        RunMlKem();
        break;
    case "ML-DSA":
        RunMldsa();
        break;
    default:
        Console.WriteLine("Nothing selected!");
        break;
}

static void RunMldsa()
{
    Console.WriteLine("***************** ML-DSA *******************");
    
    // ******** STEP 1 ********
    // Alice prepares the message
    var raw = "Hello, I'm Alice and you can verify that!";
    var data = Hex.Encode(Encoding.ASCII.GetBytes(raw));

    // ******** STEP 2 ********
    // Generate a key pair for Alice
    var random = new SecureRandom();
    var keyGenParameters = new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65);
    var mldsaKeyPairGenerator = new MLDsaKeyPairGenerator();
    mldsaKeyPairGenerator.Init(keyGenParameters);

    var keyPair = mldsaKeyPairGenerator.GenerateKeyPair();

    // View the keys for debug purposes
    var publicKey = (MLDsaPublicKeyParameters)keyPair.Public;
    var privateKey = (MLDsaPrivateKeyParameters)keyPair.Private;
    var pubEncoded = publicKey.GetEncoded();
    var privateEncoded = privateKey.GetEncoded();
    PrintPanel("Keys", new[] { $":unlocked: Public: {pubEncoded.PrettyPrint()}", $":locked: Private: {privateEncoded.PrettyPrint()}" });
    //  - Private key stays with Alice
    //  - Public key is shared with Bob
    // ******** END STEP 2 ********

    // ******** STEP 3 ********
    // Alice signs the data with the private key
    var alice = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
    alice.Init(true, privateKey);
    alice.BlockUpdate(data, 0, data.Length);
    var signature = alice.GenerateSignature();
    
    // Print the message + signature
    PrintPanel("Data", new[] { $":unlocked: Raw: {raw}", $":unlocked: Encoded: {data.PrettyPrint()}", $":pen: Signature: {signature.PrettyPrint()}" });
    //  - Private key stays with Alice
    //  - Message is shared with Bob
    //  - Signature is shared with Bob
    //  - Public key is shared with Bob
    // ******** END STEP 3 ********
    
    // ******** STEP 4 ********
    // Bob verifies the signature using the message + Alice's public key
    var bob = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
    bob.Init(false, publicKey);
    bob.BlockUpdate(data, 0, data.Length);
    var verified = bob.VerifySignature(signature);
    PrintPanel("Verification", new[] { $"{(verified ? ":check_mark_button:" : ":cross_mark:")} Verified! " });
    // ******** END STEP 4 ********
}

static void RunMlKem() 
{
    Console.WriteLine("***************** ML-KEM *******************");
    
    // ******** STEP 1 ********
    // Generate a key pair for Alice
    var random = new SecureRandom();
    var keyGenParameters = new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768);
    
    var kyberKeyPairGenerator = new MLKemKeyPairGenerator();
    kyberKeyPairGenerator.Init(keyGenParameters);

    var aliceKeyPair = kyberKeyPairGenerator.GenerateKeyPair();
    
    // View the keys for debug purposes
    var alicePublic = (MLKemPublicKeyParameters)aliceKeyPair.Public;
    var alicePrivate = (MLKemPrivateKeyParameters)aliceKeyPair.Private;
    var pubEncoded = alicePublic.GetEncoded();
    var privateEncoded = alicePrivate.GetEncoded();
    PrintPanel("Alice's keys", new[] { $":unlocked: Public: {pubEncoded.PrettyPrint()}", $":locked: Private: {privateEncoded.PrettyPrint()}" });
    //  - Private key stays with Alice
    //  - Public key is shared with Bob
    // ******** END STEP 1 ********

    // ******** STEP 2 ********
    // Bob encapsulates a shared secret using Alice's public key
    var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
    encapsulator.Init(MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, pubEncoded));
    
    var cipherText = new byte[encapsulator.EncapsulationLength];
    var bobSecret = new byte[encapsulator.SecretLength];
    encapsulator.Encapsulate(cipherText, 0, cipherText.Length, bobSecret, 0, bobSecret.Length);
    //  - Secret stays with Bob
    //  - Cipher text is sent back to Alice
    // ******** END STEP 2 ********
    
    // ******** STEP 3 ********
    // Alice decapsulates shared secret using Alice's private key
    var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
    decapsulator.Init(alicePrivate);

    var aliceSecret = new byte[decapsulator.SecretLength];
    decapsulator.Decapsulate(cipherText, 0, cipherText.Length, aliceSecret, 0, aliceSecret.Length);
    //  - Secret stays with Alice
    //  - Now Alice and Bob should possess the same secret!
    // ******** END STEP 3 ********
    
    // View the cipher text and secrets for debug purposes
    PrintPanel("Key encapsulation", new[] { $":man: Bob's secret: {bobSecret.PrettyPrint()}", $":locked_with_key: Cipher text (Bob -> Alice): {cipherText.PrettyPrint()}" });
    
    PrintPanel("Key decapsulation", new[] { $":woman: Alice's secret: {aliceSecret.PrettyPrint()}" });
    
    // Compare secrets for debug purposes
    var equal = bobSecret.SequenceEqual(aliceSecret);
    PrintPanel("Verification", new[] { $"{(equal ? ":check_mark_button:" : ":cross_mark:")} Secrets equal! " });
}

static void PrintPanel(string header, string[] data)
{
    var content = string.Join(Environment.NewLine, data);
    var panel = new Panel(content)
    {
        Header = new PanelHeader(header)
    };
    AnsiConsole.Write(panel);
}

public static class FormatExtensions
{
    public static string PrettyPrint(this byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.Length > 50 ? $"{base64[..25]}...{base64[^25..]}" : base64;
    }
}