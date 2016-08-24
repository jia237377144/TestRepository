using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetTransfer
{
    class Program
    {
        static void Main(string[] args)
        {
            #region 对称加密
            //string key = "secret key";  //密钥
            //string plainText = "hello,world";  //明文

            //string encryptedText = SymmetricCryPtoHelper.Encrypt(plainText, key);  //加密
            //Console.WriteLine("第一次加密结果： " + encryptedText);

            //string result = SymmetricCryPtoHelper.Encrypt(encryptedText, key);  //加密

            //Console.WriteLine("第二次加密结果： " + result);

            //string clearText = SymmetricCryPtoHelper.Decrypt(result, key);  //解密
            //Console.WriteLine("第一次解密结果： " + clearText);

            //string clearText1 = SymmetricCryPtoHelper.Decrypt(clearText, key);  //解密
            //Console.WriteLine("第二次解密结果： " + clearText1);

            //Console.ReadKey();
            #endregion



            #region 非对称加密
            string plainText = "hello world";
            
            string encryptedText = (new RSACryptoHelper()).Encrypt(plainText);  //机密啦~~
            Console.WriteLine(encryptedText);


            string clearText = (new RSACryptoHelper()).Decrypt(encryptedText);  //解密
            Console.WriteLine(clearText);
            Console.ReadKey();
            #endregion

            #region DES对URL加密
           
            //string encryptedStr= sec.EncryptQueryString("jialipeng");
            //Console.WriteLine(encryptedStr);
            //string decryptedStr = sec.DecryptQueryString(encryptedStr);
            //Console.WriteLine(decryptedStr);
            //Console.ReadLine();
           /* Security sec = new Security();
            string url = "index.aspx?id=5555&name=zhangsan";
            string[] arrUrl = url.Split('?');
            string[] arrParm = arrUrl[1].Split('&');
            Hashtable ht = new Hashtable();
            for (int i = 0; i < arrParm.Length; i++)
            {
                string[] keyValue = arrParm[i].Split('=');
                ht.Add(keyValue[0], keyValue[1]);
            }

            Hashtable htEncrypted = new Hashtable();

            foreach (DictionaryEntry de in ht)
            {
                string tmpStr = sec.EncryptQueryString(de.Value.ToString());
                htEncrypted.Add(de.Key.ToString(), tmpStr);
            }

            StringBuilder sbPara = new StringBuilder();
            foreach (DictionaryEntry de in htEncrypted)
            {
                sbPara.Append(de.Key.ToString() + "=" + de.Value.ToString()+"&");
            }
            string newUrl = arrUrl[0] + "?" + sbPara.ToString().Substring(0, sbPara.ToString().Length - 1);
            Console.WriteLine("加密的URL: "+newUrl);*/
            #endregion
            #region DES解密
           /* string[] arrUrlDecrypted = newUrl.Split('?');
            string[] arrParmDecrypted = arrUrlDecrypted[1].Split('&');
            Hashtable htDecrypted = new Hashtable();
            for (int i = 0; i < arrParmDecrypted.Length; i++)
            {
                string[] keyValue = arrParmDecrypted[i].Split('=');
                htDecrypted.Add(keyValue[0], keyValue[1]);
            }

            Hashtable htlDecrypted1 = new Hashtable();

            foreach (DictionaryEntry de in htDecrypted)
            {
                string tmpStr = sec.DecryptQueryString(de.Value.ToString());
                htlDecrypted1.Add(de.Key.ToString(), tmpStr);
            }

            StringBuilder sbParaDecrypted = new StringBuilder();
            foreach (DictionaryEntry de in htlDecrypted1)
            {
                sbParaDecrypted.Append(de.Key.ToString() + "=" + de.Value.ToString() + "&");
            }
            string newUrlDecrypted = arrUrlDecrypted[0] + "?" + sbParaDecrypted.ToString().Substring(0, sbParaDecrypted.ToString().Length - 1);
            Console.WriteLine("解密的URL: " + newUrlDecrypted);
            Console.ReadLine();*/
            #endregion
        }
    }
}
