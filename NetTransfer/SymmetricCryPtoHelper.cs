using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetTransfer
{
    /// <summary>
    /// 对称加密类
    /// </summary>
    public class SymmetricCryPtoHelper
    {//对称加密算法提供器
        private ICryptoTransform encryptor;//加密器对象
        private ICryptoTransform decryptor;//解密器对象
        private const int BufferSize = 1024;



        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricCryPtoHelper"> class.
        /// </see></summary>
        ///<param name="algorithmName">Name of the algorithm.
        ///<param name="key">The key.
        /// <remarks>Editor：v-liuhch</remarks>
        public SymmetricCryPtoHelper(string algorithmName, byte[] key)
        {
            //SymmetricAlgorithm为对称算法基类
            SymmetricAlgorithm provider = SymmetricAlgorithm.Create(algorithmName);
            provider.Key = key;//指定密钥，通常为128位或者196位
            provider.IV = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };//Initialization vector ,初始化向量，避免了加密之后文字的相关部分也是重复的问题，通常为64位

            encryptor = provider.CreateEncryptor();//创建加密器对象
            decryptor = provider.CreateDecryptor();//创建解密器对象

        }

        public SymmetricCryPtoHelper(byte[] key) : this("TripleDES", key) { }


        //加密算法
        /// <summary>
        /// Encrypts the specified clear text.
        /// </summary>
        ///<param name="clearText">The clear text.
        /// <returns>System.String.</returns>
        /// <remarks>Editor：v-liuhch CreateTime：2015/5/17 16:56:15</remarks>
        public string Encrypt(string clearText)
        {

            //创建明文流
            byte[] clearBuffer = Encoding.UTF8.GetBytes(clearText);
            MemoryStream clearStream = new MemoryStream(clearBuffer);

            //创建空的密文流
            MemoryStream encryptedStream = new MemoryStream();


            /* 加密解密涉及到两个流，一个是明文流，一个是密文流
            那么必然有一个中介者，将明文流转换成密文流；或者将密文流转换成明文流；
            * .net中执行这个操作的中介者是一个流类型，叫做CryptoStream；
             * 
             * 加密时构造函数参数：
             *     1，Stream:密文流（此时密文流还没有包含数据，仅仅是一个空流）；
             *     2，ICryptoTransform：创建的加密器，负责进行加密计算，
             *     3，枚举：write,将流经CryptoStream的明文流写入到密文流中，最后从密文流中获得加密后的数据
            */
            CryptoStream cryptoStream = new CryptoStream(encryptedStream, encryptor, CryptoStreamMode.Write);


            //将明文流写入到buffer中
            //将buffer中的数据写入到cryptoStream中
            int bytesRead = 0;
            byte[] buffer = new byte[BufferSize];
            do
            {
                bytesRead = clearStream.Read(buffer, 0, BufferSize);
                cryptoStream.Write(buffer, 0, bytesRead);

            } while (bytesRead > 0);

            cryptoStream.FlushFinalBlock();//清除缓冲区

            //获取加密后的文本
            buffer = encryptedStream.ToArray();
            string encryptedText = Convert.ToBase64String(buffer);
            return encryptedText;

        }


        /// <summary>
        /// 解密算法
        /// </summary>
        ///<param name="encryptedText">The encrypted text.
        /// <returns>System.String.</returns>
        /// <remarks>Editor：v-liuhch CreateTime：2015/5/17 16:56:22</remarks>
        public string Decrypt(string encryptedText)
        {
            byte[] encryptedBuffer = Convert.FromBase64String(encryptedText);
            Stream encryptedStream = new MemoryStream(encryptedBuffer);

            MemoryStream clearStream = new MemoryStream();
            /*
             解密时构造函数参数：
             *     1，Stream:密文流（此时密文流包含数据）；
             *     2，ICryptoTransform：创建的解密器，负责进行解密计算，
             *     3，枚举：write,将密文流中的数据读出到明文流，进而再转换成明文的，原来的格式
             */
            CryptoStream cryptoStream = new CryptoStream(encryptedStream, decryptor, CryptoStreamMode.Read);

            int bytesRead = 0;
            byte[] buffer = new byte[BufferSize];

            do
            {
                bytesRead = cryptoStream.Read(buffer, 0, BufferSize);
                clearStream.Write(buffer, 0, bytesRead);

            } while (bytesRead > 0);

            buffer = clearStream.GetBuffer();
            string clearText = Encoding.UTF8.GetString(buffer, 0, (int)clearStream.Length);

            return clearText;


        }


        /// <summary>
        /// Encrypts the specified clear text.
        /// </summary>
        ///<param name="clearText">The clear text.
        ///<param name="key">The key.
        /// <returns>System.String.</returns>
        /// <remarks>Editor：v-liuhch CreateTime：2015/5/17 16:56:40</remarks>
        public static string Encrypt(string clearText, string key)
        {


            byte[] keyData = new byte[16];
            byte[] sourceData = Encoding.Default.GetBytes(key);
            int copyBytes = 16;
            if (sourceData.Length < 16)
            {
                copyBytes = sourceData.Length;

            }

            Array.Copy(sourceData, keyData, copyBytes);
            SymmetricCryPtoHelper helper = new SymmetricCryPtoHelper(keyData);
            return helper.Encrypt(clearText);

        }


        /// <summary>
        /// Decrypts the specified encrypted text.
        /// </summary>
        ///<param name="encryptedText">The encrypted text.
        ///<param name="key">The key.
        /// <returns>System.String.</returns>
        /// <remarks>Editor：v-liuhch CreateTime：2015/5/17 16:56:44</remarks>
        public static string Decrypt(string encryptedText, string key)
        {

            byte[] keyData = new byte[16];
            byte[] sourceData = Encoding.Default.GetBytes(key);
            int copyBytes = 16;
            if (sourceData.Length < 16)
            {
                copyBytes = sourceData.Length;
            }

            Array.Copy(sourceData, keyData, copyBytes);

            SymmetricCryPtoHelper helper = new SymmetricCryPtoHelper(keyData);
            return helper.Decrypt(encryptedText);

        }
    }
}
