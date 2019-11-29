//
// System.Net.Radius.RadiusUtils.cs
//
// Author:
//  Cyrille Colin (colin@univ-metz.fr)
//
// Copyright (C) Cyrille COLIN, 2005
//

using System.Security.Cryptography;

namespace System.Net.Radius
{

    internal class Utils
    {
        internal static byte[] MakeRFC2865RequestAuthenticator(string sharedSecret)
        {
            var sharedS = Text.Encoding.ASCII.GetBytes(sharedSecret);
            var requestAuthenticator = new byte[16 + sharedS.Length];
            var r = new Random();
            for (int i = 0; i < 16; i++)
                requestAuthenticator[i] = (byte)r.Next();
            Array.Copy(sharedS, 0, requestAuthenticator, 16, sharedS.Length);
            MD5 md5 = new MD5CryptoServiceProvider();
            md5.ComputeHash(requestAuthenticator);
            return md5.Hash;
        }

        internal static byte[] MakeRFC2865ResponseAuthenticator(byte[] data, byte[] requestAuthenticator, string sharedSecret)
        {
            var md5 = new MD5CryptoServiceProvider();
            var ssArray = Text.Encoding.ASCII.GetBytes(sharedSecret);
            var sum = new byte[data.Length + ssArray.Length];
            Array.Copy(data, 0, sum, 0, data.Length);
            Array.Copy(requestAuthenticator, 0, sum, 4, 16);
            Array.Copy(ssArray, 0, sum, data.Length, ssArray.Length);
            md5.ComputeHash(sum);
            return md5.Hash;
        }

        internal static byte[] EncodePapPassword(byte[] userPassBytes, byte[] requestAuthenticator, string sharedSecret)
        {
            if (userPassBytes.Length > 128)
                throw new InvalidOperationException("the PAP password cannot be greater than 128 bytes...");

            byte[] encryptedPass = null;
            if (userPassBytes.Length % 16 == 0)
            {
                encryptedPass = new byte[userPassBytes.Length];
            }
            else
            {
                encryptedPass = new byte[((userPassBytes.Length / 16) * 16) + 16];
            }
            Array.Copy(userPassBytes, 0, encryptedPass, 0, userPassBytes.Length);
            for (int i = userPassBytes.Length; i < encryptedPass.Length; i++)
            {
                encryptedPass[i] = 0;
            }

            byte[] sharedSecretBytes = System.Text.Encoding.ASCII.GetBytes(sharedSecret);

            System.Security.Cryptography.MD5 md5;
            for (int chunk = 0; chunk < (encryptedPass.Length / 16); chunk++)
            {
                md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
                md5.TransformBlock(sharedSecretBytes, 0, sharedSecretBytes.Length, sharedSecretBytes, 0);
                if (chunk == 0)
                    md5.TransformFinalBlock(requestAuthenticator, 0, requestAuthenticator.Length);
                else
                    md5.TransformFinalBlock(encryptedPass, (chunk - 1) * 16, 16);

                byte[] hash = md5.Hash;

                for (int i = 0; i < 16; i++)
                {
                    int j = i + chunk * 16;
                    encryptedPass[j] = (byte)(hash[i] ^ encryptedPass[j]);
                }

            }

            return encryptedPass;
        }
    }
}
