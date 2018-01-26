package cn.tarena.ht.shiro;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

import cn.tarena.ht.tool.MD5Utils;

public class AuthCredentialMatcher extends SimpleCredentialsMatcher{

	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		
		//把用户输入的密码 进行加密
		UsernamePasswordToken loginToken = (UsernamePasswordToken) token;
		//把用户输入的密码取出 char[]转成String
		String password = String.valueOf(loginToken.getPassword());
		password = MD5Utils.getMd5(password, password);
		//修改令牌中的密码
		loginToken.setPassword(password.toCharArray());
		return super.doCredentialsMatch(token, info);
	}
}
