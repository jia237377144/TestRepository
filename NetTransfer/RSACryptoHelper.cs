using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetTransfer
{
    /// <summary>
    /// 非对称加密帮助类
    /// </summary>
    public class RSACryptoHelper
    {
        #region  密钥获取方法  ==未进行封装
        //方法一：
        //string privateKey = provider.ToXmlString(true);//获得公/私钥对
        //string publicKey = provider.ToXmlString(false);//获得公钥对
        //方法二：
        //RSAParameters privateKey = provider.ExportParameters(true);//获得公钥私钥对
        //RSAParameters publicKey = provider.ExportParameters(false);//获得公钥
        #endregion
        public string privateKey { get; set; }
        public string publicKey { get; set; }
        public RSACryptoHelper()
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            this.privateKey = provider.ToXmlString(true); ;
            this.publicKey = provider.ToXmlString(false);
        }

        /// <summary>
        /// 发送方加密
        /// </summary>
        ///<param name="publicKeyXml">The public key XML.
        ///<param name="plainText">The plain text.
        /// <returns>System.String.</returns>
        /// <remarks>Editor：v-liuhch CreateTime：2015/5/16 22:06:54</remarks>
        public  string Encrypt(string plainText)
        {
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(publicKey); //使用公钥初始化对象
            byte[] plainData = Encoding.Default.GetBytes(plainText);
            byte[] encryptedData = provider.Encrypt(plainData, false);//对数据进行加密
            return Convert.ToBase64String(encryptedData);
        }


        /// <summary>
        /// 接收方解密
        /// </summary>
        ///<param name="privateKeyXml">The private key XML.
        ///<param name="encryptedText">The encrypted text.
        /// <returns>System.String.</returns>
        /// <remarks>Editor：v-liuhch CreateTime：2015/5/16 22:11:09</remarks>
        public string Decrypt( string encryptedText)
        {

            RSACryptoServiceProvider provider = new RSACryptoServiceProvider();
            provider.FromXmlString(privateKey);//使用私钥对数据进行初始化
            byte[] encryptedData = Convert.FromBase64String(encryptedText);
            byte[] plainData = provider.Decrypt(encryptedData, false);  //对数据进行解密
            string plainText = Encoding.Default.GetString(plainData);  //明文
            return plainText;
        }
    }
}
