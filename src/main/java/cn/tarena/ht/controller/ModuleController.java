package cn.tarena.ht.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import cn.tarena.ht.pojo.Module;
import cn.tarena.ht.service.ModuleService;

@Controller
@RequestMapping("/sysadmin/module")
public class ModuleController {
	
	@Autowired
	private ModuleService moduleService;
	@RequestMapping("/list")
	public String findAll(Model model){
		
		List<Module> modules = moduleService.findAll();
		model.addAttribute("moduleList",modules);
		return "/sysadmin/module/jModuleList";
	}
	@RequestMapping("/stop")
	public String stop(@RequestParam(value="moduleId",required=false)String[] moduleIds){
		
		if(moduleIds!=null){
			moduleService.changeState(0,moduleIds);
		}
		return "redirect:/sysadmin/module/list";
	}
	@RequestMapping("/start")
	public String start(@RequestParam(value="moduleId",required=false)String[] moduleIds){
		
		if(moduleIds!=null){
			moduleService.changeState(1,moduleIds);
		}
		return "redirect:/sysadmin/module/list";
	}
	@RequestMapping("/delete")
	public String delete(@RequestParam(value="moduleId",required=false)String[] moduleIds){
		
		if(moduleIds!=null){
			moduleService.delete(moduleIds);
		}
		return "redirect:/sysadmin/module/list";
	}
	@RequestMapping("/tocreate")
	public String toCreate(Model model){
		
		List<Module> modules = moduleService.findAll();
		model.addAttribute("moduleList",modules);
		
		return "/sysadmin/module/jModuleCreate";
	}
	@RequestMapping("/tosave")
	public String toSave(Module module){
		
		moduleService.save(module);
		
		return "redirect:/sysadmin/module/list";
	}
	@RequestMapping("/toupdate")
	public String toUpdate(String moduleId,Model model){
		
		if(moduleId==null){
			return "redirect:/sysadmin/module/list";
		}
		Module module = moduleService.findOne(moduleId);
		model.addAttribute("module",module);
		
		List<Module> modules = moduleService.findAll();
		model.addAttribute("moduleList",modules);
		return "/sysadmin/module/jModuleUpdate";
	}
	
	@RequestMapping("update")
	public String update(Module module){
		
		moduleService.update(module);
		
		return "redirect:/sysadmin/module/list";
	}
	
	@RequestMapping("/toview")
	public String toView(String moduleId,Model model){
		
		Module module = moduleService.findOne(moduleId);
		model.addAttribute("module", module);
		
		return "/sysadmin/module/jModuleView";
	}
}








