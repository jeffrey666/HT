package cn.tarena.ht.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import cn.tarena.ht.pojo.User;

public interface UserMapper {
	public List<User> findAll();

	public void changeState(@Param("state")int i, @Param("userIds")String[] userIds);

	public void deleteUser(String[] userIds);

	public void saveUser(User user);

	public User findOne(String userId);

	public void update(User user);

	public void saveUserRole(@Param("userId")String userId,@Param("roleIds")String[] roleIds);
	
	@Delete("delete from role_user_p where user_id =#{userId}")
	public void deleteUserRole(String userId);
	@Select("select role_id from role_user_p where user_id=#{userId}")
	public List<String> findAllRole(String userId);

	public void deleteDept(String[] deptIds);

	public void deleteUserRoleByUId(String[] userIds);

	public User findUser(@Param("username")String username, @Param("password")String password);

	public User findOneByUsername(String username);

	public List<String> findModulesBy(String userId);
}
