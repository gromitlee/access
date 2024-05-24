package model

import "github.com/gromitlee/access/pkg/perm"

// RolePerm 角色 Role Based Access Control 0 DB Model
type RolePerm struct {
	ID int64 `gorm:"primary_key"`

	Role perm.Role `gorm:"index:idx_role_perm_role;not null"`
	Obj  perm.Obj  `gorm:"index:idx_role_perm_obj;not null"`
	Act  perm.Act  `gorm:"index:idx_role_perm_act;not null"`
}
