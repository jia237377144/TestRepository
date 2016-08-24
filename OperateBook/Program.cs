using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OperateBook
{
    class Program
    {
        static void Main(string[] args)
        {
            #region 读取证书
            /*OperCert cert = new OperCert();
            string filePath = @"G:\NoIncludePrivateKey.cer";
             string privateKey = @"G:\IncludePrivateKey.pfx";
             cert.CerTest(privateKey, "PRIVATEKEY");
            Console.ReadLine();*/
            #endregion

            #region 证书加密

            //string publicKey = @"G:\NoIncludePrivateKey.cer";
            //string privateKey = @"G:\IncludePrivateKey.pfx";
            //RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
        
            //X509Certificate2 x509 = DataCertificate.GetCertificateFromStore("RSAKey");
            //provider.FromXmlString(x509.PublicKey.Key.ToXmlString(false));
            //string pwd = "123qwe@#";
            //string plainText="hello World";
            //OperCert cert = new OperCert();
            //byte[] encryptArr = new UnicodeEncoding().GetBytes(plainText);
            //byte[] encryptedStr = provider.Encrypt(encryptArr, true);
            //string encryptedString = Convert.ToBase64String(encryptedStr);
            //Console.WriteLine("密文： " + encryptedString);
            //Console.ReadLine();
            ////byte[] decryptedStr = provider.Decrypt(encryptedStr, true);
            //string decryptedStr1 = RSADecrypt(x509.PrivateKey.ToXmlString(true), encryptedString);
            //Console.WriteLine("明文：" + decryptedStr1);
            //Console.ReadLine();

            #endregion

            #region MyRegion

            // 在personal（个人）里面创建一个foo的证书  
            DataCertificate.CreateCertWithPrivateKey("foo", "C:\\Program Files (x86)\\Windows Kits\\8.1\\bin\\x64\\makecert.exe");

            // 获取证书  
            X509Certificate2 c1 = DataCertificate.GetCertificateFromStore("foo");

            string keyPublic = c1.PublicKey.Key.ToXmlString(false);  // 公钥  
            string keyPrivate = c1.PrivateKey.ToXmlString(true);  // 私钥  

            string cypher = RSAEncrypt(keyPublic, "jialipeng1");  // 加密  
            string plain = RSADecrypt(keyPrivate, cypher);  // 解密  

            Debug.Assert(plain == "jialipeng1");

            // 生成一个cert文件  
            DataCertificate.ExportToCerFile("foo", "d:\\mycert\\foo.cer");

            X509Certificate2 c2 = DataCertificate.GetCertFromCerFile("d:\\mycert\\foo.cer");

            string keyPublic2 = c2.PublicKey.Key.ToXmlString(false);

            bool b = keyPublic2 == keyPublic;
            string cypher2 = RSAEncrypt(keyPublic2, "jialipeng12");  // 加密  
            //string cypher2 = RSAEncrypt(keyPublic2, "jialipeng12");  // 加密  
            string plain2 = RSADecrypt(keyPrivate, cypher2);  // 解密, cer里面并没有私钥，所以这里使用前面得到的私钥来解密  

            Debug.Assert(plain2 == "jialipeng12");

            // 生成一个pfx， 并且从store里面删除  
            DataCertificate.ExportToPfxFile("foo", "d:\\mycert\\foo.pfx", "123123", true);

            X509Certificate2 c3 = DataCertificate.GetCertificateFromPfxFile("d:\\mycert\\foo.pfx", "123123");

            string keyPublic3 = c3.PublicKey.Key.ToXmlString(false);  // 公钥  
            string keyPrivate3 = c3.PrivateKey.ToXmlString(true);  // 私钥  

            string cypher3 = RSAEncrypt(keyPublic3, "jialipeng13");  // 加密  
            string plain3 = RSADecrypt(keyPrivate3, cypher3);  // 解密  

            Debug.Assert(plain3 == "jialipeng13");

            #endregion

        }

        static string RSADecrypt(string xmlPrivateKey, string m_strDecryptString)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPrivateKey);
            //byte[] rgb = Convert.FromBase64String(m_strDecryptString);
            //byte[] bytes = provider.Decrypt(rgb, false);
            //return new UnicodeEncoding().GetString(bytes);

            Byte[] CiphertextData = Convert.FromBase64String(m_strDecryptString);
            int MaxBlockSize = provider.KeySize / 8;    //解密块最大长度限制

            if (CiphertextData.Length <= MaxBlockSize)
                return new UnicodeEncoding().GetString(provider.Decrypt(CiphertextData, false));

            using (MemoryStream CrypStream = new MemoryStream(CiphertextData))
            using (MemoryStream PlaiStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[MaxBlockSize];
                int BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);

                while (BlockSize > 0)
                {
                    Byte[] ToDecrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToDecrypt, 0, BlockSize);

                    Byte[] Plaintext = provider.Decrypt(ToDecrypt, false);
                    PlaiStream.Write(Plaintext, 0, Plaintext.Length);

                    BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);
                }

                return new UnicodeEncoding().GetString(PlaiStream.ToArray());
            }
        }
        /// <summary>     
        /// RSA加密     
        /// </summary>     
        /// <param name="xmlPublicKey"></param>     
        /// <param name="m_strEncryptString"></param>     
        /// <returns></returns>     
        static string RSAEncrypt(string xmlPublicKey, string m_strEncryptString)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(xmlPublicKey);
            //byte[] bytes = new UnicodeEncoding().GetBytes(m_strEncryptString);
            Byte[] PlaintextData = new UnicodeEncoding().GetBytes(m_strEncryptString);
            int MaxBlockSize = provider.KeySize / 8 - 11;    //加密块最大长度限制

            if (PlaintextData.Length <= MaxBlockSize)
                return Convert.ToBase64String(provider.Encrypt(PlaintextData, false));

            using (MemoryStream PlaiStream = new MemoryStream(PlaintextData))
            using (MemoryStream CrypStream = new MemoryStream())
            {
                Byte[] Buffer = new Byte[MaxBlockSize];
                int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);

                while (BlockSize > 0)
                {
                    Byte[] ToEncrypt = new Byte[BlockSize];
                    Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);

                    Byte[] Cryptograph = provider.Encrypt(ToEncrypt, false);
                    CrypStream.Write(Cryptograph, 0, Cryptograph.Length);

                    BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                }
                return Convert.ToBase64String(CrypStream.ToArray(), Base64FormattingOptions.None);
            }
        }
    }
}
