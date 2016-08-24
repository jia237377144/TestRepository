using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace OperateBook
{
    public class OperCert
    {
        public byte[] ReadFile(string fileName)
        {
            FileStream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)fs.Length;
            byte[] data = new byte[size];
            size = fs.Read(data, 0, size);
            fs.Close();
            return data;
        }
        /// <summary>
        /// 输出证书信息
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="certificateType"></param>
        public void CerTest(string filePath, string certificateType)
        {
            try
            {
                X509Certificate2 x509 = null;
                switch (certificateType)
                {
                    case "PUBLICKEY":
                        x509 = new X509Certificate2();
                        break;
                    case "PRIVATEKEY":
                        string pwd = "123qwe@#";
                        x509 = new X509Certificate2(filePath, pwd);
                        break;
                }
                byte[] rawData = ReadFile(filePath);
                x509.Import(rawData);
                //证书主题
                Console.WriteLine("{0} 证书主题: {1} {0}", Environment.NewLine, x509.Subject);
                //颁发机构
                Console.WriteLine("{0} 颁发机构:  {1} {0}", Environment.NewLine, x509.Issuer);
                //版本
                Console.WriteLine("{0} 版本:  {1} {0}", Environment.NewLine, x509.Version);
                //获取证书生效的本地时间中的日期。
                Console.WriteLine("{0} 生效日期:  {1} {0}", Environment.NewLine, x509.NotBefore);
                //结束日期
                Console.WriteLine("{0} 结束日期:  {1} {0}", Environment.NewLine, x509.NotAfter);
                //获取证书指纹
                Console.WriteLine("{0} 获取证书指纹:  {1} {0}", Environment.NewLine, x509.Thumbprint);
                //序列号
                Console.WriteLine("{0} 序列号:  {1} {0}", Environment.NewLine, x509.SerialNumber);
                //友好名称
                Console.WriteLine("{0} 友好名称:  {1} {0}", Environment.NewLine, x509.PublicKey.Oid.FriendlyName);
                //编码格式
                Console.WriteLine("{0} 编码格式:  {1} {0}", Environment.NewLine, x509.PublicKey.EncodedKeyValue.Format(true));
                //长度
                Console.WriteLine("{0} 长度:  {1} {0}", Environment.NewLine, x509.RawData.Length);
                //文本
                Console.WriteLine("{0} 文本:  {1} {0}", Environment.NewLine, x509.ToString(true));
                //xml
                Console.WriteLine("{0} xml:  {1} {0}", Environment.NewLine, x509.PublicKey.Key.ToXmlString(false));
                //证书存储区
                X509Store store = new X509Store();
                //打开
                store.Open(OpenFlags.MaxAllowed);
                //读取
                store.Add(x509);
                store.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error:  " + ex.Message);
            }
        }

        /// <summary>
        /// 根据安全证书创建加密RSA
        /// </summary>
        /// <param name="certfile">公钥文件</param>
        /// <returns></returns>
        private RSACryptoServiceProvider X509CertCreateEncryptRSA(string certfile)
        {
            try
            {
                X509Certificate2 x509Cert = new X509Certificate2(certfile);
                RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)x509Cert.PublicKey.Key;
                return RSA;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// 根据私钥文件创建解密RSA
        /// </summary>
        /// <param name="keyfile">私钥文件</param>
        /// <param name="password">访问含私钥文件的密码</param>
        /// <returns></returns>
        private RSACryptoServiceProvider X509CertCreateDecryptRSA(string keyfile, string password)
        {
            try
            {
                X509Store store = new X509Store();
                //打开
                store.Open(OpenFlags.MaxAllowed);
                X509Certificate2 x509Cert = new X509Certificate2(keyfile, password);
                //读取
                store.Add(x509Cert);
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                string xmlString = x509Cert.PrivateKey.ToXmlString(false);
                RSA.FromXmlString(xmlString);  
                store.Close();
                return RSA;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }
        /// <summary>
        /// 根据安全证书加密
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="certfile"></param>
        /// <returns></returns>
        public string X509CertEncrypt(string dataToEncrypt, string certfile)
        {
            Encoding encoder = Encoding.UTF8;
            byte[] _dataToEncrypt = encoder.GetBytes(dataToEncrypt);
            return this.X509CertEncrypt(_dataToEncrypt, certfile);
        }
        /// <summary>
        /// 根据安全证书加密
        /// </summary>
        /// <param name="dataToEncrypt">待加密数据</param>
        /// <param name="certfile">安全证书</param>
        /// <returns></returns>
        public string X509CertEncrypt(byte[] dataToEncrypt, string certfile)
        {
            if (!File.Exists(certfile))
            {
                throw new ArgumentNullException(certfile, "加密证书未找到");
            }
            using (RSACryptoServiceProvider RSA = this.X509CertCreateEncryptRSA(certfile))
            {
                byte[] encryptedData = RSA.Encrypt(dataToEncrypt, false);
                //return this.BytesToHexString(encryptedData);
                return BitConverter.ToString(encryptedData, 0, encryptedData.Length);
            }
        }
        /// <summary>
        /// 创建解密RSA
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        private RSACryptoServiceProvider CreateDecryptRSA(string privateKey)
        {
            try
            {
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSA.FromXmlString(privateKey);
                return RSA;
            }
            catch (CryptographicException ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns></returns>
        public string Decrypt(string encryptedData, string privateKey)
        {
            using (RSACryptoServiceProvider RSA = this.CreateDecryptRSA(privateKey))
            {
                Encoding encoder = Encoding.UTF8;
                byte[] _encryptedData = HexStringToBytes(encryptedData);
                byte[] decryptedData = RSA.Decrypt(_encryptedData, false);
                return encoder.GetString(decryptedData);
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="keyfile">私钥文件</param>
        /// <param name="password">访问私钥文件密码</param>
        /// <returns></returns>
        public string X509CertDecrypt(string encryptedData, string keyfile, string password)
        {
            if (!File.Exists(keyfile))
            {
                throw new ArgumentNullException(keyfile, "解密证书未找到");
            }
            using (RSACryptoServiceProvider RSA = this.X509CertCreateDecryptRSA(keyfile, password))
            {
                Encoding encoder = Encoding.UTF8;
                byte[] _encryptedData = HexStringToBytes(encryptedData);
                byte[] decryptedData = RSA.Decrypt(_encryptedData, false);
                return encoder.GetString(decryptedData);
            }
        }
        /// <summary>
        /// 16进制字符串转换为字节数组
        /// </summary>
        /// <param name="mHex"></param>
        /// <returns></returns>
        public static byte[] HexStringToBytes(string mHex)
        {
            {
                mHex = mHex.Replace(" ", "");
                if (mHex.Length % 2 != 0) { mHex = ""; };
                byte[] vBytes = new byte[mHex.Length / 2];
                string TempStr = "";
                for (int i = 0; i < mHex.Length; i += 2)
                {
                    TempStr = mHex.Substring(i, 2);
                    vBytes[i / 2] = Convert.ToByte(TempStr, 16);// byte.Parse(TempStr, NumberStyles.HexNumber);
                }
                return vBytes;
            }
        }
    }
}
