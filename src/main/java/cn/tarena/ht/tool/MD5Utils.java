package cn.tarena.ht.tool;

import org.apache.shiro.crypto.hash.Md5Hash;

public class MD5Utils {
	private MD5Utils(){
	}
	public static String getMd5(String password,String salt){
		//第一位参数为原密码，第二位为加入参数（可任意），第三位为循环加密次数
		Md5Hash mh = new Md5Hash(password, salt, 2);
		return mh.toString();
	}
}
