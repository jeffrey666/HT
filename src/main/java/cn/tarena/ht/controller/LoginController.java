package cn.tarena.ht.controller;

import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;

import cn.tarena.ht.pojo.User;
import cn.tarena.ht.service.UserService;
import cn.tarena.ht.tool.MD5Utils;

@Controller
public class LoginController {
	@Autowired
	private UserService userService;
/*	@RequestMapping("login")
	public String login(String username,String password,Model model,HttpSession session){
		
		if(StringUtils.isEmpty(username)||StringUtils.isEmpty(password)){
			model.addAttribute("errorInfo","用户名或密码不能为空");
			
			return "/sysadmin/login/login";
		}
		//进行MD5加密
		password=(MD5Utils.getMd5(password, password));
		System.out.println("========="+password+"==========");
		User user = userService.findUser(username,password);
		
		if(user==null){
			
			model.addAttribute("errorInfo","用户名或密码不正确");
			
			return "/sysadmin/login/login";
		}
		
		session.setAttribute("_CURRENT_USER", user);
		return "redirect:/home";
	}*/
	
	@RequestMapping("login")
	public String login(String username,String password,Model model,HttpSession session){
		//代表当前用户
		Subject subject = SecurityUtils.getSubject();
		//制造令牌
		UsernamePasswordToken token = new UsernamePasswordToken(username,password);
		
		try {
			//正常登录
			subject.login(token);
			//获取用户对象
			User user = (User) subject.getPrincipal();
			//存放进session中，方便其他页面获取登录用户信息
			session.setAttribute("_CURRENT_USER", user);
			//跳转到主页面
			return "redirect:/home";
		} catch (AuthenticationException e) {
			//登录错误
			e.printStackTrace();
			
			model.addAttribute("errorInfo","用户名或密码不能为空");
			//回到登录页面
			return "/sysadmin/login/login";
			
		}
		
		
	}
	
	@RequestMapping("logout")
	public String logout(HttpSession session){
		session.removeAttribute("_CURRENT_USER");
		//通知shiro框架 退出登录
		Subject subject = SecurityUtils.getSubject();
		//判断是否是登录状态，是则退出
		if(subject.isAuthenticated()){
			subject.logout();
		}
		
		
		return "/sysadmin/login/logout";
	}
}
