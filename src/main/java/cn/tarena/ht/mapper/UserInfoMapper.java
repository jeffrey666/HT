package cn.tarena.ht.mapper;

import cn.tarena.ht.pojo.UserInfo;

public interface UserInfoMapper {
	public void deleteUserInfo(String[] userIds);

	public void saveUserInfo(UserInfo userInfo);

	public void update(UserInfo userInfo);
}
