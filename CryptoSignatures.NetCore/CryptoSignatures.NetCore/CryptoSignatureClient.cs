using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace CryptoSignatures.NetCore
{
    public class CryptoSignatureClient
    {
        /// <summary>
        /// Get a signature for a message
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="secureString">SecureString of api key secret</param>
        /// <param name="exchange">Exchange to sign for</param>
        /// <param name="blockchain">Blockchain type (defatul = nil)</param>
        /// <returns>String of signature</returns>
        public string GetSignature(string message, SecureString secureString, Exchange exchange, Blockchain blockchain = Blockchain.nil)
        {
            string keySecret = string.Empty;
            switch(exchange)
            {
                case Exchange.BIBOX:
                    return string.Empty;
                case Exchange.BINANCE:
                    keySecret = SecureStringToString(secureString);
                    return GetBinanceHMACSignature(message, keySecret);
                case Exchange.COINBASE:
                    keySecret = SecureStringToString(secureString);
                    return GetCoinbaseHMACSignature(message, keySecret);
                case Exchange.COINBENE:
                    return string.Empty;
                case Exchange.COINEX:
                    keySecret = SecureStringToString(secureString);
                    return GetCoinExHMACSignature(message);
                case Exchange.KUCOIN:
                    keySecret = SecureStringToString(secureString);
                    return GetKuCoinHMACSignature(message, keySecret);
                case Exchange.SWITCHEO:
                    var privateKey = SecureStringToByteArray(secureString);
                    return GetSwitcheoSignature(message, privateKey, blockchain);
                default:
                    return string.Empty;
            }
        }

        /// <summary>
        /// Get a signature for Switcheo Exchange
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="privateKey">Private key byte array</param>
        /// <param name="blockchain">Blockchain type (defatul = neo)</param>
        /// <returns>String of signature</returns>
        private string GetSwitcheoSignature(string message, byte[] privateKey, Blockchain blockchain = Blockchain.neo)
        {
            var msgBytes = HexToBytes(message);

            switch (blockchain)
            {
                case Blockchain.ethereum:
                    return string.Empty;
                case Blockchain.neo:
                    return GetSwitcheoNeoSignature(msgBytes, privateKey);
                case Blockchain.qtum:
                    return string.Empty;
                default:
                    return string.Empty;
            }
        }

        /// <summary>
        /// SecureString to string
        /// </summary>
        /// <param name="secureString">SecureString value</param>
        /// <returns>converted string</returns>
        private string SecureStringToString(SecureString secureString)
        {
            IntPtr valuePtr = IntPtr.Zero;

            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        /// <summary>
        /// SecureString to byte[]
        /// </summary>
        /// <param name="secureString">SecureString value</param>
        /// <returns>converted byte[]</returns>
        private byte[] SecureStringToByteArray(SecureString secureString)
        {
            IntPtr valuePtr = IntPtr.Zero;

            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Encoding.UTF8.GetBytes(Marshal.PtrToStringUni(valuePtr));
            }
            finally
            {
                Marshal.ZeroFreeBSTR(valuePtr);
            }
        }

        /// <summary>
        /// Convert a string to a byte array
        /// </summary>
        /// <param name="value">String value to convert</param>
        /// <returns>Converted byte array</returns>
        private byte[] HexToBytes(string value)
        {
            if (value == null || value.Length == 0)
                return new byte[0];
            if (value.Length % 2 == 1)
                throw new FormatException();
            byte[] result = new byte[value.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = byte.Parse(value.Substring(i * 2, 2), NumberStyles.AllowHexSpecifier);
            return result;
        }

        /// <summary>
        /// Get Binance HMAC Signature
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="keySecret">Api key secret</param>
        /// <returns>string of signed message</returns>
        private string GetBinanceHMACSignature(string message, string keySecret)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();
            byte[] messageBytes = encoding.GetBytes(message);
            byte[] keyBytes = encoding.GetBytes(keySecret);
            HMACSHA256 crypotgrapher = new HMACSHA256(keyBytes);

            byte[] bytes = crypotgrapher.ComputeHash(messageBytes);

            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        /// <summary>
        /// Get Coinbase HMAC Signature
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="keySecret">Api key secret</param>
        /// <returns>string of signed message</returns>
        private string GetCoinbaseHMACSignature(string message, string secretKey)
        {
            byte[] keyByte = Convert.FromBase64String(secretKey);
            byte[] messageByte = Encoding.UTF8.GetBytes(message);
            using (var hmac = new HMACSHA256(keyByte))
            {
                byte[] hashMessage = hmac.ComputeHash(messageByte);
                return Convert.ToBase64String(hashMessage);
            }
        }

        /// <summary>
        /// Get CoinEx HMAC Signature
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <returns>string of signed message</returns>
        private string GetCoinExHMACSignature(string message)
        {
            using (var md5 = MD5.Create())
            {
                var msgBytes = Encoding.ASCII.GetBytes(message);
                var hashBytes = md5.ComputeHash(msgBytes);

                var sb = new StringBuilder();
                for (var i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }

                return sb.ToString();
            }
        }

        /// <summary>
        /// Get KuCoin HMAC Signature
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="secretKey">Api secret</param>
        /// <returns>Signature for request</returns>
        private string GetKuCoinHMACSignature(string message, string secretKey)
        {
            var msgString = Convert.ToBase64String(Encoding.UTF8.GetBytes(message));

            byte[] keyBytes = Encoding.UTF8.GetBytes(secretKey);
            byte[] msgBytes = Encoding.UTF8.GetBytes(msgString);

            using (var hmac = new HMACSHA256(keyBytes))
            {
                byte[] hash = hmac.ComputeHash(msgBytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }

        /// <summary>
        /// Get Switcheo NEO Signature
        /// </summary>
        /// <param name="message">Message to sign</param>
        /// <param name="privateKey">Private key of wallet</param>
        /// <returns>String  of signed message</returns>
        private string GetSwitcheoNeoSignature(byte[] message, byte[] privateKey)
        {
            var curve = SecNamedCurves.GetByName("secp256r1");
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

            var priv = new ECPrivateKeyParameters("ECDSA", (new Org.BouncyCastle.Math.BigInteger(1, privateKey)), domain);
            var signer = new ECDsaSigner();

            var hash = new Sha256Digest();
            hash.BlockUpdate(message, 0, message.Length);

            var result = new byte[32];
            hash.DoFinal(result, 0);

            message = result;

            signer.Init(true, priv);
            var signature = signer.GenerateSignature(message);

            return ProcessNeoSignature(signature);
        }

        /// <summary>
        /// Process a Neo signature
        /// </summary>
        /// <param name="signature">BigInteger array to process</param>
        /// <returns>String of processed signature</returns>
        private string ProcessNeoSignature(BigInteger[] signature)
        {
            var fullsign = new byte[64];

            var r = signature[0].ToByteArray();
            var s = signature[1].ToByteArray();
            var rLen = r.Length;
            var sLen = s.Length;

            if (rLen < 32)
            {
                Array.Copy(r, 0, fullsign, 32 - rLen, rLen);
            }
            else
            {
                Array.Copy(r, rLen - 32, fullsign, 0, 32);
            }

            if (sLen < 32)
            {
                Array.Copy(s, 0, fullsign, 64 - sLen, sLen);
            }
            else
            {
                Array.Copy(s, sLen - 32, fullsign, 32, 32);
            }

            var signedResult = fullsign;

            var signedMessage = BitConverter.ToString(signedResult);

            return signedMessage.Replace("-", "").ToLower();
        }
    }
}
