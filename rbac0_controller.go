package access

import (
	"context"

	access_rbac0 "github.com/gromitlee/access/internal/ctl/access/rbac0"
	casbin_rbac0 "github.com/gromitlee/access/internal/ctl/casbin/rbac0"
	"github.com/gromitlee/access/pkg/perm"
	"gorm.io/gorm"
)

// IRBAC0Controller RBAC0权限控制器 interface
type IRBAC0Controller interface {
	// CheckPerm 检查权限
	// 返回 ok, enable, isAdmin, err
	CheckPerm(ctx context.Context, role perm.Role, obj perm.Obj, act perm.Act) (bool, bool, bool, error)
	CheckPermTx(db *gorm.DB, role perm.Role, obj perm.Obj, act perm.Act) (bool, bool, bool, error)
	// CheckPerms 检查权限，有一个role有权限即为true(例如一个用户是多个角色的情况)
	CheckPerms(ctx context.Context, roles []perm.Role, obj perm.Obj, act perm.Act) (bool, error)
	CheckPermsTx(db *gorm.DB, roles []perm.Role, obj perm.Obj, act perm.Act) (bool, error)

	// CreateRole 创建角色
	// 当role为0时，由系统分配role的枚举值；role非0适用于系统已经固定角色枚举值，不需要动态创建角色的需求
	// 当isAdmin为true时，该角色(内置admin)具有一切权限
	CreateRole(ctx context.Context, role perm.Role, creator int64, name, desc string, isAdmin bool, perms ...perm.Perm) (*perm.RolePerms, error)
	CreateRoleTx(db *gorm.DB, role perm.Role, creator int64, name, desc string, isAdmin bool, perms ...perm.Perm) (*perm.RolePerms, error)
	// UpdateRole 更新角色
	UpdateRole(ctx context.Context, role perm.Role, name, desc string) error
	UpdateRoleTx(db *gorm.DB, role perm.Role, name, desc string) error
	// DeleteRole 删除角色
	DeleteRole(ctx context.Context, role perm.Role) error
	DeleteRoleTx(db *gorm.DB, role perm.Role) error

	// ListRoleInfo 查询角色列表
	ListRoleInfo(ctx context.Context, name string, enable int32, offset, limit, order int64) ([]*perm.RoleInfo, int64, error)
	ListRoleInfoTx(db *gorm.DB, name string, enable int32, offset, limit, order int64) ([]*perm.RoleInfo, int64, error)
	// GetRoleInfo 查询角色信息
	GetRoleInfo(ctx context.Context, role perm.Role) (*perm.RoleInfo, error)
	GetRoleInfoTx(db *gorm.DB, role perm.Role) (*perm.RoleInfo, error)
	// GetRoleInfos 查询角色信息
	GetRoleInfos(ctx context.Context, roles []perm.Role, order int64) ([]*perm.RoleInfo, error)
	GetRoleInfosTx(db *gorm.DB, roles []perm.Role, order int64) ([]*perm.RoleInfo, error)

	// ListRolePerms 查询角色列表
	ListRolePerms(ctx context.Context, name string, enable int32, offset, limit, order int64) ([]*perm.RolePerms, int64, error)
	ListRolePermsTx(db *gorm.DB, name string, enable int32, offset, limit, order int64) ([]*perm.RolePerms, int64, error)
	// GetRolePerms 查询角色权限
	GetRolePerms(ctx context.Context, role perm.Role) (*perm.RolePerms, error)
	GetRolePermsTx(db *gorm.DB, role perm.Role) (*perm.RolePerms, error)

	// GrantRolePerms 授予角色权限，会自动去重，对内置admin无效
	GrantRolePerms(ctx context.Context, role perm.Role, perms []perm.Perm) error
	GrantRolePermsTx(db *gorm.DB, role perm.Role, perms []perm.Perm) error
	// RevokeRolePerms 撤销角色权限
	RevokeRolePerms(ctx context.Context, role perm.Role, perms []perm.Perm) error
	RevokeRolePermsTx(db *gorm.DB, role perm.Role, perms []perm.Perm) error
	// CleanRolePerms 清除角色所有权限(对内置admin无效)
	CleanRolePerms(ctx context.Context, role perm.Role) error
	CleanRolePermsTx(db *gorm.DB, role perm.Role) error

	// EnableRole 启用角色，新增角色默认启用
	EnableRole(ctx context.Context, role perm.Role) error
	EnableRoleTx(db *gorm.DB, role perm.Role) error
	// DisableRole 禁用角色
	DisableRole(ctx context.Context, role perm.Role) error
	DisableRoleTx(db *gorm.DB, role perm.Role) error
}

// NewCasbinRBAC0Controller 基于 db + casbin 的RBAC0实现
func NewCasbinRBAC0Controller(db *gorm.DB, modelPath string) (IRBAC0Controller, error) {
	return casbin_rbac0.NewController(db, modelPath)
}

// NewAccessRBAC0Controller 基于 db 的RBAC0实现
func NewAccessRBAC0Controller(db *gorm.DB) (IRBAC0Controller, error) {
	return access_rbac0.NewController(db)
}
