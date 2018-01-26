<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../baselist.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>新增用户</title>
</head>

<body>
<form name="icform" method="post">

<div id="menubar">
<div id="middleMenubar">
<div id="innerMenubar">
  <div id="navMenubar">
<ul>
	<li id="save"><a href="#" onclick="formSubmit('tosave','_self');this.blur();">新增</a></li>
	<li id="back"><a href="#" onclick="window.history.back();">后退</a></li>
	
</ul>
  </div>
</div>
</div>
</div>
   
  <div class="textbox-title">
	<img src="../../staticfile/skin/default/images/icon/currency_yen.png"/>
    新增用户
  </div> 
  
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	<tr>
		<td>用户名:</td>
		<td><input type="text" name="username" /></td>
		<td>用户密码:</td>
		<td><input type="password" name="password" /></td>
	</tr>
	<tr>
		<td>真实姓名:</td>
		<td><input type="text" name="userInfo.name" /></td>
		<td>身份证号:</td>
		<td><input type="text" name="userInfo.cardNo" /></td>
	</tr>
	<tr>
		<td>生日:</td>
		<td><input type="date" name="userInfo.birthday" /></td>
		<td>入职时间:</td>
		<td><input type="date" name="userInfo.joinDate" /></td>
	</tr>
	<tr>
		<td>电话号码:</td>
		<td><input type="text" name="userInfo.telephone" /></td>
		<td>工资:</td>
		<td><input type="text" name="userInfo.salary" /></td>
	</tr>
	<tr>
		<td>个人描述:</td>
		<td><input type="text" name="userInfo.station" /></td>
		<td>性别:</td>
		<td>
			<input type="radio" name="userInfo.gender" value="男"/>男
			<input type="radio" name="userInfo.gender" value="女"/>女
		</td>
	</tr>
	<tr>
		<td>所属部门:</td>
		<td>
			<select name="dept.deptId" >
				<option >--无--</option>
				<c:forEach items="${deptList }" var="d" >
					<option value="${d.deptId }" >${d.deptName }</option>
				</c:forEach>
				
			</select>
		</td>
		<td>直属领导:</td>
		<td>
			<select name="userInfo.manager.userInfoId" >
				<option >--无--</option>
				<c:forEach items="${users }" var="u" >
					<option value="${u.userId }" >${u.userInfo.name }</option>
				</c:forEach>
				
			</select>
		</td>
	</tr>
	<tr>
		<td>员工职位:</td>
		<td>
			<select name="userInfo.userLevel" >
				<option value="4">普通用户</option>
				<option value="3">部门经理</option>
				<option value="2">副总经理</option>
				<option value="1">公司总裁</option>
				<option value="0">超级管理员</option>
			</select>
		</td>
		<td>员工状态:</td>
		<td >
			<input type="radio" name="state" value="1"/>启用
			<input type="radio" name="state" value="0"/>停用
		</td>
	</tr>
	<tr >
		<td>备注:</td>
		<td colspan="2">
			<textarea style="width:100%;height:100px" name="userInfo.remark"></textarea>
		</td>
		
	</tr>
</table>
</div>
 
</div>
 
 
</form>
</body>
</html>

