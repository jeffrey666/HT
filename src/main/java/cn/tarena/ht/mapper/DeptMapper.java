package cn.tarena.ht.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Param;

import cn.tarena.ht.pojo.Dept;

public interface DeptMapper {
	
	public List<Dept> findAll();
	
	public void updateState(@Param("state") Integer i, @Param("deptId") String[] deptIds);

	public void delete(String[] deptIds);

	public void insertDept(Dept dept);

	public Dept selectOne(String deptId);

	public void update(Dept dept);
}
