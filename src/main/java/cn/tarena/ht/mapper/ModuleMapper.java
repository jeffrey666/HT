package cn.tarena.ht.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Update;

import cn.tarena.ht.pojo.Module;

public interface ModuleMapper {
	
	public List<Module> findAll();

	public void changeState(@Param("state")int i,@Param("moduleIds") String[] moduleIds);

	public void delete(String[] moduleIds);

	@Insert("insert into module_p (module_id,parent_id,name,ctype,state,order_no,remark,create_time) values(#{moduleId},#{parentModule.moduleId},#{name},#{ctype},#{state},#{orderNo},#{remark},#{createTime})")
	public void save(Module module);

	public Module findOne(String moduleId);
	@Update("update module_p set parent_id=#{parentModule.moduleId},name=#{name},ctype=#{ctype},state=#{state},order_no=#{orderNo},remark=#{remark} where module_id=#{moduleId}")
	public void update(Module module);

	public void deleteModuleRole(String[] moduleIds);
}
