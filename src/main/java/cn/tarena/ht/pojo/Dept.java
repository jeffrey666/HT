package cn.tarena.ht.pojo;

public class Dept extends BaseEntity{
	private String deptName;
	private String deptId;
	private Integer state;
	private Dept parentDept;
	public String getDeptName() {
		return deptName;
	}
	public void setDeptName(String deptName) {
		this.deptName = deptName;
	}
	public String getDeptId() {
		return deptId;
	}
	public void setDeptId(String deptId) {
		this.deptId = deptId;
	}
	public Integer getState() {
		return state;
	}
	public void setState(Integer state) {
		this.state = state;
	}
	public Dept getParentDept() {
		return parentDept;
	}
	public void setParentDept(Dept parentDept) {
		this.parentDept = parentDept;
	}
	public String toString() {
		return "Dept [deptName=" + deptName + ", deptId=" + deptId + ", state=" + state + ", parentDept=" + parentDept
				+ "]";
	}
	
}
