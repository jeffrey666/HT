package cn.tarena.ht.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import cn.tarena.ht.pojo.Role;

public interface RoleMapper {
	@Select("select * from role_p")
	public List<Role> findAll();

	public void delete(String[] roleIds);
	
	@Insert("insert into role_p (role_id,name,remarks,order_no,create_time) values(#{roleId},#{name},#{remarks},#{orderNo},#{createTime})")
	public void insertRole(Role role);
	
	@Select("select * from role_p where role_id = #{roleId}")
	public Role findOne(String roleId);
	
	@Update("update role_p set name=#{name},remarks=#{remarks} ,order_no=#{orderNo} where role_id=#{roleId}")
	public void update(Role role);

	public void saveRoleModule(@Param("roleId")String roleId,@Param("moduleIds")String[] moduleIds);
	@Delete("delete from role_module_p where role_id=#{roleId}")
	public void deleteRoleModule(String roleId);
	@Select("select module_id from role_module_p where role_id =#{roleId}")
	public List<String> findRoleModule(String roleId);

	public void deleteRoleModules(String[] roleIds);

	public void deleteRoleUser(String[] roleIds);
}
