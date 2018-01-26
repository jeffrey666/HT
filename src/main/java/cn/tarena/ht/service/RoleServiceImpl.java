package cn.tarena.ht.service;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import cn.tarena.ht.mapper.RoleMapper;
import cn.tarena.ht.pojo.Role;
@Service
public class RoleServiceImpl implements RoleService{

	@Autowired
	private RoleMapper roleMapper;
	@Override
	public List<Role> findAll() {
		return roleMapper.findAll();
	}
	@Override
	public void delete(String[] roleIds) {
		//先删除角色模块关系表
		roleMapper.deleteRoleModules(roleIds);
		//再删除角色用户关系表
		roleMapper.deleteRoleUser(roleIds);
		roleMapper.delete(roleIds);
	}
	@Override
	public void insertRole(Role role) {
		role.setCreateTime(new Date());
		role.setRoleId(UUID.randomUUID().toString());
		roleMapper.insertRole(role);
	}
	@Override
	public Role findOne(String roleId) {
		return roleMapper.findOne(roleId);
	}
	@Override
	public void update(Role role) {
		roleMapper.update(role);
	}
	@Override
	public void saveRoleModule(String roleId, String[] moduleIds) {
		roleMapper.deleteRoleModule(roleId);
		if(moduleIds.length>0){
			roleMapper.saveRoleModule(roleId,moduleIds);
		}
		
	}
	@Override
	public List<String> findRoleModule(String roleId) {
		return roleMapper.findRoleModule(roleId);
	}

}
