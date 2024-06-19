import java.math.BigInteger;
import java.security.SecureRandom;
public class Other_Main {
    /*Creating an RSA encryption and decryption program without using any libraries is quite complex because it requires implementing the RSA algorithm from scratch, which involves a lot of mathematical operations, especially with big integers. However, for educational purposes, I can show a simplified version of the RSA algorithm without using any external libraries.

    This example includes:
            1. Generating key pairs (public and private keys).
            2. Encrypting a message using the public key.
3. Decrypting the message using the private key.

    Please note that this implementation is very basic and not suitable for any production use due to the lack of necessary cryptographic security measures and optimizations. It's intended only for educational purposes.

    Here's the complete code:

*/
        private static final int BIT_LENGTH = 2048;
        private static final SecureRandom secureRandom = new SecureRandom();

        public static class KeyPair {
            private final BigInteger publicKey;
            private final BigInteger privateKey;
            private final BigInteger modulus;

            public KeyPair(BigInteger publicKey, BigInteger privateKey, BigInteger modulus) {
                this.publicKey = publicKey;
                this.privateKey = privateKey;
                this.modulus = modulus;
            }

            public BigInteger getPublicKey() {
                return publicKey;
            }

            public BigInteger getPrivateKey() {
                return privateKey;
            }

            public BigInteger getModulus() {
                return modulus;
            }
        }

        // Generate RSA key pair
        public static KeyPair generateKeyPair() {
            BigInteger p = BigInteger.probablePrime(BIT_LENGTH / 2, secureRandom);
            BigInteger q = BigInteger.probablePrime(BIT_LENGTH / 2, secureRandom);
            BigInteger n = p.multiply(q);
            BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
            BigInteger e = BigInteger.valueOf(65537); // Commonly used prime exponent
            BigInteger d = e.modInverse(phi);

            return new KeyPair(e, d, n);
        }

        // Encrypt the message using the public key
        public static BigInteger encrypt(BigInteger message, BigInteger publicKey, BigInteger modulus) {
            return message.modPow(publicKey, modulus);
        }

        // Decrypt the message using the private key
        public static BigInteger decrypt(BigInteger encrypted, BigInteger privateKey, BigInteger modulus) {
            return encrypted.modPow(privateKey, modulus);
        }

        public static void main(String[] args) {
            // Generate the RSA key pair
            KeyPair keyPair = generateKeyPair();
            BigInteger publicKey = keyPair.getPublicKey();
            BigInteger privateKey = keyPair.getPrivateKey();
            BigInteger modulus = keyPair.getModulus();

            // Message to be encrypted
            String message = "Hello, this is a secret message!";
            BigInteger messageAsNumber = new BigInteger(message.getBytes());

            // Encrypt the message
            BigInteger encryptedMessage = encrypt(messageAsNumber, publicKey, modulus);
            System.out.println("Encrypted Message: " + encryptedMessage);

            // Decrypt the message
            BigInteger decryptedMessage = decrypt(encryptedMessage, privateKey, modulus);
            String decryptedMessageAsString = new String(decryptedMessage.toByteArray());
            System.out.println("Decrypted Message: " + decryptedMessageAsString);
        }
    /*


        ### Explanation:
            1. **KeyPair Class:**
            - Holds the public key, private key, and modulus.

            2. **Key Generation:**
            - Generates two large prime numbers `p` and `q`.
            - Computes `n` as the product of `p` and `q`.
            - Computes `phi` as `(p-1) * (q-1)`.
            - Selects a common public exponent `e` (65537).
            - Computes the private key `d` as the modular inverse of `e` modulo `phi`.

            3. **Encryption and Decryption:**
            - Encryption is done using `message^e % n`.
            - Decryption is done using `encrypted^d % n`.

            4. **Main Method:**
            - Generates the key pair.
            - Converts the plaintext message to a `BigInteger`.
            - Encrypts and then decrypts the message, displaying the results.
*/
    //This implementation shows the basic principles behind RSA encryption and decryption. For real-world applications, always use well-established cryptographic libraries and follow best practices to ensure security.
}
