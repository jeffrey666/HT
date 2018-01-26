package cn.tarena.ht.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import cn.tarena.ht.pojo.Dept;
import cn.tarena.ht.service.DeptService;

@Controller
@RequestMapping("/sysadmin/dept")
public class DeptController {
	@Autowired
	private DeptService deptService;
	
	@RequestMapping("/list")
	public String findAll(Model model){
		
		List<Dept> depts = deptService.findAll();
		model.addAttribute("deptList",depts);
		
		return "/sysadmin/dept/jDeptList";
	}
	
	@RequestMapping("/stop")
	public String stop(@RequestParam(value="deptId",required=false)String[] deptIds){
		
		if(deptIds!=null){
			deptService.changeState(0,deptIds);
		}
		return "redirect:/sysadmin/dept/list";
	}
	
	@RequestMapping("/start")
	public String start(@RequestParam(value="deptId",required=false)String[] deptIds){
		if(deptIds!=null){
			deptService.changeState(1,deptIds);
		}
		return "redirect:/sysadmin/dept/list";
	}

	
	
	@RequestMapping("/delete")
	public String delete(@RequestParam(value="deptId",required=false)String[] deptIds){
		if(deptIds!=null){
			deptService.delete(deptIds);
		}
		return "redirect:/sysadmin/dept/list";
	}
	
	@RequestMapping("/tocreate")
	public String toCreate(Model model){
		
		List<Dept> depts = deptService.findAll();
		model.addAttribute("deptList",depts);
		
		return "sysadmin/dept/jDeptCreate";
	}
	
	@RequestMapping("/tosave")
	public String toSave(Dept dept){
		
		deptService.save(dept);
		
		return "redirect:/sysadmin/dept/list";
	}
	
	@RequestMapping("toview")
	public String toView(String deptId ,Model model){
		if(deptId!=null){
			Dept dept = deptService.findOne(deptId);
			model.addAttribute("dept",dept);
		}
		return "sysadmin/dept/jDeptView";
	}
	
	@RequestMapping("/toupdate")
	public String toUpdate(String deptId,Model model){
		
		if(deptId!=null){
			Dept dept = deptService.findOne(deptId);
			model.addAttribute("dept",dept);
			List<Dept> depts = deptService.findAll();
			model.addAttribute("parentDepts",depts);
		}
		
		
		return "sysadmin/dept/jDeptUpdate";
	}
	
	@RequestMapping("/update")
	public String update(Dept dept){
		
		deptService.update(dept);
		
		return "redirect:/sysadmin/dept/list";
	}
}



















