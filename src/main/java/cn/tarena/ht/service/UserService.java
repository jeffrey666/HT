package cn.tarena.ht.service;

import java.util.List;

import cn.tarena.ht.pojo.User;

public interface UserService {
	public List<User> findAll();

	public void changeState(int i, String[] userIds);

	public void delete(String[] userIds);

	public void saveUser(User user);

	public User findOne(String userId);

	public void update(User user);

	public void saveUserRole(String userId, String[] roleIds);

	public List<String> findAllRole(String userId);

	public User findUser(String username, String password);

	public User findOneByUsername(String username);

	public List<String> findModulesByUId(String userId);

}
