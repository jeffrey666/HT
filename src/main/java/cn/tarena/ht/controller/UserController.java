package cn.tarena.ht.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import cn.tarena.ht.pojo.Dept;
import cn.tarena.ht.pojo.Role;
import cn.tarena.ht.pojo.User;
import cn.tarena.ht.service.DeptService;
import cn.tarena.ht.service.RoleService;
import cn.tarena.ht.service.UserService;

@Controller
@RequestMapping("/sysadmin/user")
public class UserController extends BaseController{
	@Autowired
	private DeptService deptService;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	private RoleService roleService;
	@RequestMapping("/list")
	public String findAll(Model model){
		
		List<User> users = userService.findAll();
		model.addAttribute("users",users);
		
		return "/sysadmin/user/jUserList";
	}
	
	
	@RequestMapping("/stop")
	public String stopAction(@RequestParam(value="userId",required=false)String[] userIds){
		if(userIds!=null){
			userService.changeState(0,userIds);
		}
		return "redirect:/sysadmin/user/list";
	}
	
	@RequestMapping("/start")
	public String startAction(@RequestParam(value="userId",required=false)String[] userIds){
		if(userIds!=null){
			userService.changeState(1,userIds);
		}
		return "redirect:/sysadmin/user/list";
	}
	
	@RequestMapping("/delete")
	public String deleteAction(@RequestParam(value="userId",required=false)String[] userIds){
		if(userIds!=null){
			userService.delete(userIds);
		}
		return "redirect:/sysadmin/user/list";
	}
	
	@RequestMapping("/tocreate")
	public String toCreate(Model model){
		
		
		List<User> users = userService.findAll();
		model.addAttribute("users",users);
		
		List<Dept> depts= deptService.findAll();
		model.addAttribute("deptList",depts);
		
		return "/sysadmin/user/jUserCreate";
	}
	
	@RequestMapping("/tosave")
	public String toSave(User user){
		
		userService.saveUser(user);
		
		return "redirect:/sysadmin/user/list";
	}
	
	@RequestMapping("/toupdate")
	public String toUpdate(String userId,Model model){
		
		User user=userService.findOne(userId);
		model.addAttribute("user",user);
		
		List<User> users = userService.findAll();
		model.addAttribute("userList",users);
		
		List<Dept> depts= deptService.findAll();
		model.addAttribute("deptList",depts);
		
		return "/sysadmin/user/jUserUpdate";
	}
	
	@RequestMapping("/update")
	public String update(User user){
		
		userService.update(user);
		
		return "redirect:/sysadmin/user/list";
	}
	
	
	@RequestMapping("/toview")
	public String toView(String userId,Model model){
		
		User user=userService.findOne(userId);
		model.addAttribute("user",user);
		
		return "/sysadmin/user/jUserView";
	}
	
	@RequestMapping("/role")
	public String addRole(String userId,Model model) throws JsonProcessingException{
		
		if(userId==null){
			return "redirect:/sysadmin/user/list";
		}
		List<String> roleIdList=userService.findAllRole(userId);
		model.addAttribute("userId", userId);
		List<Role> roles = roleService.findAll();
		for (Role role : roles) {
			if(roleIdList.contains(role.getId())){
				role.setChecked(true);
			}
		}
		
		ObjectMapper mapper= new ObjectMapper();
		String jsonString = mapper.writeValueAsString(roles);
		model.addAttribute("zTreeJson",jsonString);
		
		return "/sysadmin/user/jUserRole";
	}
	
	@RequestMapping("/saveUserRole")
	public String saveUserRole(String userId,String[] roleIds){
			
		userService.saveUserRole(userId,roleIds);
		
		return "redirect:/sysadmin/user/list";
	}
}























