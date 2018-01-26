package cn.tarena.ht.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import cn.tarena.ht.mapper.DeptMapper;
import cn.tarena.ht.mapper.UserMapper;
import cn.tarena.ht.pojo.Dept;
@Service
public class DeptServiceImpl implements DeptService{
	@Autowired
	private DeptMapper deptMapper;
	@Autowired
	private UserMapper userMapper;
	@Override
	public List<Dept> findAll() {
		return deptMapper.findAll();
	}

	@Override
	public void changeState(int i, String[] deptIds) {
		
		deptMapper.updateState(i,deptIds);
	}

	@Override
	public void delete(String[] deptIds) {
		//先更改User表中的部门id为空
		userMapper.deleteDept(deptIds);
		
		deptMapper.delete(deptIds);
	}

	@Override
	public void save(Dept dept) {
			
		deptMapper.insertDept(dept);
	}

	@Override
	public Dept findOne(String deptId) {
		
		return deptMapper.selectOne(deptId);
	}

	@Override
	public void update(Dept dept) {
		deptMapper.update(dept);
	}

}
