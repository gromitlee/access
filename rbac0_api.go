package access

import (
	"errors"

	"github.com/gromitlee/access/pkg/perm"
	"gorm.io/gorm"
)

// 单例模式
var _rbac0Ctl IRBAC0Controller

func InitCasbinRBAC0Controller(db *gorm.DB, modelPath string) error {
	if _rbac0Ctl != nil {
		return errors.New("rbac0 ctl already init")
	}
	var err error
	_rbac0Ctl, err = NewCasbinRBAC0Controller(db, modelPath)
	return err
}

func InitAccessRBAC0Controller(db *gorm.DB) error {
	if _rbac0Ctl != nil {
		return errors.New("rbac0 ctl already init")
	}
	var err error
	_rbac0Ctl, err = NewAccessRBAC0Controller(db)
	return err
}

func RBAC0CheckPerm(db *gorm.DB, role perm.Role, obj perm.Obj, act perm.Act) (bool, bool, bool, error) {
	if _rbac0Ctl == nil {
		return false, false, false, errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.CheckPermTx(db, role, obj, act)
}

func RBAC0CheckPerms(db *gorm.DB, roles []perm.Role, obj perm.Obj, act perm.Act) (bool, error) {
	if _rbac0Ctl == nil {
		return false, errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.CheckPermsTx(db, roles, obj, act)
}

func RBAC0CreateRole(db *gorm.DB, role perm.Role, creator int64, name, desc string, isAdmin bool, perms ...perm.Perm) (*perm.RolePerms, error) {
	if _rbac0Ctl == nil {
		return nil, errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.CreateRoleTx(db, role, creator, name, desc, isAdmin, perms...)
}

func RBAC0UpdateRole(db *gorm.DB, role perm.Role, name, desc string) error {
	if _rbac0Ctl == nil {
		return errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.UpdateRoleTx(db, role, name, desc)
}

func RBAC0DeleteRole(db *gorm.DB, role perm.Role) error {
	if _rbac0Ctl == nil {
		return errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.DeleteRoleTx(db, role)
}

func RBAC0ListRoleInfo(db *gorm.DB, name string, enable int32, offset, limit, order int64) ([]*perm.RoleInfo, int64, error) {
	if _rbac0Ctl == nil {
		return nil, 0, errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.ListRoleInfoTx(db, name, enable, offset, limit, order)
}

func RBAC0GetRoleInfo(db *gorm.DB, role perm.Role) (*perm.RoleInfo, error) {
	if _rbac0Ctl == nil {
		return nil, errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.GetRoleInfoTx(db, role)
}

func RBAC0GetRoleInfos(db *gorm.DB, roles []perm.Role, order int64) ([]*perm.RoleInfo, error) {
	if _rbac0Ctl == nil {
		return nil, errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.GetRoleInfosTx(db, roles, order)
}

func RBAC0ListRolePerms(db *gorm.DB, name string, enable int32, offset, limit, order int64) ([]*perm.RolePerms, int64, error) {
	if _rbac0Ctl == nil {
		return nil, 0, errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.ListRolePermsTx(db, name, enable, offset, limit, order)
}

func RBAC0GetRolePerms(db *gorm.DB, role perm.Role) (*perm.RolePerms, error) {
	if _rbac0Ctl == nil {
		return nil, errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.GetRolePermsTx(db, role)
}

func RBAC0GrantRolePerms(db *gorm.DB, role perm.Role, perms []perm.Perm) error {
	if _rbac0Ctl == nil {
		return errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.GrantRolePermsTx(db, role, perms)
}

func RBAC0RevokeRolePerms(db *gorm.DB, role perm.Role, perms []perm.Perm) error {
	if _rbac0Ctl == nil {
		return errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.RevokeRolePermsTx(db, role, perms)
}

func RBAC0CleanRolePerms(db *gorm.DB, role perm.Role) error {
	if _rbac0Ctl == nil {
		return errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.CleanRolePermsTx(db, role)
}

func RBAC0EnableRole(db *gorm.DB, role perm.Role) error {
	if _rbac0Ctl == nil {
		return errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.EnableRoleTx(db, role)
}

func RBAC0DisableRole(db *gorm.DB, role perm.Role) error {
	if _rbac0Ctl == nil {
		return errors.New("rbac0 ctl not init")
	}
	return _rbac0Ctl.DisableRoleTx(db, role)
}
