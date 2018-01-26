<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../baselist.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title>模块详情</title>
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
   模块详情
  </div> 
  
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	<tr>
		<td>模块名:</td>
		<td>${module.name }</td>
		<td>类型:</td>
		<td>
			<c:if test="${module.ctype==1 }">主菜单</c:if>
			<c:if test="${module.ctype==2 }">左侧菜单</c:if>
			<c:if test="${module.ctype==3 }">按钮</c:if>
		
		</td>
	</tr>
	
	<tr>
		<td>排序:</td>
		<td>${module.orderNo }</td>
		
		<td>上级模块:</td>
		<td>
			${module.parentModule.name }
		</td>
	</tr>
	<tr>
		<td>模块状态:</td>
		<td >
			<c:if test="${module.state==1 }"><font color="green">启用</font></c:if>
			<c:if test="${module.state==0 }"><font color="red">停用</font></c:if>
		</td>
	</tr>
	<tr>
		<td>备注:</td>
		<td>
			${module.remark }
		</td>
	</tr>
	
</table>
</div>
 
</div>
 
 
</form>
</body>
</html>

