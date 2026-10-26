package model

import "github.com/gromitlee/access/pkg/perm"

// RolePerm 表示 RBAC0 的角色权限关联记录。
type RolePerm struct {
	ID int64 `gorm:"primary_key"`

	// 角色 ID 使用 BIGINT 保存，以支持 int64 雪花 ID。
	Role perm.Role `gorm:"index:idx_role_perm_role;not null;type:bigint"`
	Obj  perm.Obj  `gorm:"index:idx_role_perm_obj;not null"`
	Act  perm.Act  `gorm:"index:idx_role_perm_act;not null"`
}
