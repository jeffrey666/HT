<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../baselist.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>用户信息</title>
</head>

<body>
<form name="icform" method="post">

<div id="menubar">
<div id="middleMenubar">
<div id="innerMenubar">
  <div id="navMenubar">
<ul>
	<li id="back"><a href="#" onclick="window.history.back();">后退</a></li>
	
</ul>
  </div>
</div>
</div>
</div>
   
  <div class="textbox-title">
	<img src="../../staticfile/skin/default/images/icon/currency_yen.png"/>
    用户信息
  </div> 
  
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	<tr>
		<td>用户名:</td>
		<td>${user.username }</td>
		<td>用户密码:</td>
		<td>${user.password }</td>
	</tr>
	<tr>
		<td>真实姓名:</td>
		<td>${user.userInfo.name }</td>
		<td>身份证号:</td>
		<td>${user.userInfo.cardNo }</td>
	</tr>
	<tr>
		<td>生日:</td>
		<td>
			<fmt:formatDate value="${user.userInfo.birthday }" pattern="yyyy-MM-dd"/>
		</td>
		<td>入职时间:</td>
		<td>
			<fmt:formatDate value="${user.userInfo.joinDate }" pattern="yyyy-MM-dd"/>
		</td>
	</tr>
	<tr>
		<td>电话号码:</td>
		<td>${user.userInfo.telephone }</td>
		<td>工资:</td>
		<td>${user.userInfo.salary }</td>
	</tr>
	<tr>
		<td>个人描述:</td>
		<td>${user.userInfo.station }</td>
		<td>性别:</td>
		<td>
			${user.userInfo.gender }
		</td>
	</tr>
	<tr>
		<td>所属部门:</td>
		<td>
			${user.dept.deptName }
		</td>
		<td>直属领导:</td>
		<td>
			${user.userInfo.manager.name }
		</td>
	</tr>
	<tr>
		<td>员工职位:</td>
		<td>
			<c:if test="${user.userInfo.userLevel==4 }">普通员工</c:if>
			<c:if test="${user.userInfo.userLevel==3 }">部门经理</c:if>
			<c:if test="${user.userInfo.userLevel==2 }">副总经理</c:if>
			<c:if test="${user.userInfo.userLevel==1 }">公司总裁</c:if>
			<c:if test="${user.userInfo.userLevel==0 }">超级管理员</c:if>
		</td>
		<td>员工状态:</td>
		<td >
			<c:if test="${user.state==1 }">启用</c:if>
			<c:if test="${user.state==0 }">停用</c:if>
			
		</td>
	</tr>
	<tr >
		<td>备注:</td>
		<td colspan="3">
			${user.userInfo.remark }
		</td>
		
	</tr>
</table>
</div>
 
</div>
 
 
</form>
</body>
</html>

