package cn.tarena.ht.service;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import cn.tarena.ht.mapper.ModuleMapper;
import cn.tarena.ht.pojo.Module;
@Service
public class ModuleServiceImpl implements ModuleService{

	@Autowired
	private ModuleMapper moduleMapper;
	@Override
	public List<Module> findAll() {
		return moduleMapper.findAll();
	}
	@Override
	public void changeState(int i, String[] moduleIds) {
		moduleMapper.changeState(i,moduleIds);
	}
	@Override
	public void delete(String[] moduleIds) {
		//先删除模块角色关系
		moduleMapper.deleteModuleRole(moduleIds);
		moduleMapper.delete(moduleIds);
	}
	@Override
	public void save(Module module) {
		module.setCreateTime(new Date());
		module.setModuleId(UUID.randomUUID().toString());
		moduleMapper.save(module);
	}
	@Override
	public Module findOne(String moduleId) {
		return moduleMapper.findOne(moduleId);
	}
	@Override
	public void update(Module module) {
		moduleMapper.update(module);
	}

}
