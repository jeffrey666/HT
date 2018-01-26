package cn.tarena.ht.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import cn.tarena.ht.pojo.Module;
import cn.tarena.ht.pojo.Role;
import cn.tarena.ht.service.ModuleService;
import cn.tarena.ht.service.RoleService;

@Controller
@RequestMapping("/sysadmin/role")
public class RoleController {
	@Autowired
	private ModuleService moduleService;
	@Autowired
	private RoleService roleService;
	
	@RequestMapping("/list")
	public String findAll(Model model){
		
		List<Role> roles = roleService.findAll();
		model.addAttribute("roles",roles);
		return "/sysadmin/role/jRoleList";
	}
	
	@RequestMapping("/delete")
	public String delete(@RequestParam(value="roleId",required=false)String[] roleIds){
		
		if(roleIds!=null){
			roleService.delete(roleIds);
		}
		
		return "redirect:/sysadmin/role/list";
	}
	@RequestMapping("/tocreate")
	public String toCreate(){
			
		
		return "/sysadmin/role/jRoleCreate";
	}
	@RequestMapping("/tosave")
	public String save(Role role){
			
		roleService.insertRole(role);
		
		return "redirect:/sysadmin/role/list";
	}
	
	@RequestMapping("/toupdate")
	public String toUpdate(String roleId,Model model){
		
		Role role=roleService.findOne(roleId);
		model.addAttribute("role",role);
		
		return "/sysadmin/role/jRoleUpdate";
	}
	@RequestMapping("/update")
	public String update(Role role){
		
		roleService.update(role);
		return "redirect:/sysadmin/role/list";
	}
	
	@RequestMapping("/toview")
	public String toView(String roleId,Model model){
		
		Role role=roleService.findOne(roleId);
		model.addAttribute("role",role);
		
		return "/sysadmin/role/jRoleView";
	}
	
	@RequestMapping("/tomodule")
	public String toModule(String roleId,Model model) throws JsonProcessingException{
		//显示所有的模块
		List<Module> modules = moduleService.findAll();
		//查找该角色已拥有的模块id
		List<String> moduleIds = roleService.findRoleModule(roleId);
		
		for (Module module : modules) {
			
			if(moduleIds.contains(module.getId())){
				module.setChecked(true);
			}
		}
		ObjectMapper mapper = new ObjectMapper();
		String jsonString = mapper.writeValueAsString(modules);
		model.addAttribute("zTreeJson",jsonString);
		model.addAttribute("roleId",roleId);
		return "/sysadmin/role/jRoleModule";
	}
	
	@RequestMapping("/saveRoleModule")
	public String saveRoleModule(String roleId,String[] moduleIds){
		
		
		roleService.saveRoleModule(roleId,moduleIds);
		return "redirect:/sysadmin/role/list";
	}
}













