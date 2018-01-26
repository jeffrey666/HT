package cn.tarena.ht.service;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import cn.tarena.ht.mapper.UserInfoMapper;
import cn.tarena.ht.mapper.UserMapper;
import cn.tarena.ht.pojo.User;
import cn.tarena.ht.pojo.UserInfo;
import cn.tarena.ht.tool.MD5Utils;
@Service
public class UserServiceImpl implements UserService{
	@Autowired
	private UserMapper userMapper;
	
	@Autowired
	private UserInfoMapper userInfoMapper;
	@Override
	public List<User> findAll() {
		return userMapper.findAll();
	}
	@Override
	public void changeState(int i, String[] userIds) {
		userMapper.changeState(i,userIds);
	}
	@Override
	public void delete(String[] userIds) {
		//先删除用户信息表
		userInfoMapper.deleteUserInfo(userIds);
		//还要删除角色用户关系表
		userMapper.deleteUserRoleByUId(userIds);
		userMapper.deleteUser(userIds);
	}
	@Override
	public void saveUser(User user) {
		String userId=UUID.randomUUID().toString();
		user.setUserId(userId);
		Date date = new Date();
		user.setCreateTime(date);
		user.setPassword(MD5Utils.getMd5(user.getPassword(),user.getPassword()));
		userMapper.saveUser(user);
		UserInfo userInfo = user.getUserInfo();
		
		userInfo.setUserInfoId(userId);
		userInfoMapper.saveUserInfo(userInfo);
		
	}
	@Override
	public User findOne(String userId) {
		return userMapper.findOne(userId);
	}
	@Override
	public void update(User user) {
		userMapper.update(user);
		UserInfo userInfo = user.getUserInfo();
		
		userInfo.setUserInfoId(user.getUserId());
		userInfoMapper.update(userInfo);
	}
	@Override
	public void saveUserRole(String userId, String[] roleIds) {
		userMapper.deleteUserRole(userId);
		if(roleIds!=null&&roleIds.length>0){
			userMapper.saveUserRole(userId,roleIds);
		}
	}
	@Override
	public List<String> findAllRole(String userId) {
		return userMapper.findAllRole(userId);
	}
	@Override
	public User findUser(String username, String password) {
		return userMapper.findUser(username,password);
	}
	@Override
	public User findOneByUsername(String username) {
		return userMapper.findOneByUsername(username);
	}
	@Override
	public List<String> findModulesByUId(String userId) {
		return userMapper.findModulesBy(userId);
	}

}
