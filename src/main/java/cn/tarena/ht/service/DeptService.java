package cn.tarena.ht.service;

import java.util.List;

import cn.tarena.ht.pojo.Dept;

public interface DeptService {
	
	public List<Dept> findAll();

	public void changeState(int i, String[] deptId);

	public void delete(String[] deptIds);

	public void save(Dept dept);

	public Dept findOne(String deptId);

	public void update(Dept dept);
	
}
