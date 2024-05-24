package perm

// Role 角色
type Role uint32

// Obj 资源
type Obj string

// Act 角色对资源可进行对操作
type Act string

// Perm 权限
type Perm struct {
	Obj Obj
	Act Act
}

// RolePerms 角色权限
type RolePerms struct {
	CreatedAt int64
	Role      Role
	Enable    bool
	IsAdmin   bool
	Creator   int64
	Name      string
	Desc      string
	Perms     []Perm
}

// RoleInfo 角色信息
type RoleInfo struct {
	CreatedAt int64
	Role      Role
	Enable    bool
	IsAdmin   bool
	Creator   int64
	Name      string
	Desc      string
}
