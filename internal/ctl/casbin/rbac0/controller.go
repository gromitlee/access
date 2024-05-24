package rbac0

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gromitlee/access/internal/db/model"
	"github.com/gromitlee/access/pkg/perm"
	"gorm.io/gorm"
)

const (
	autoLoadInterval = time.Second * 3
)

type Controller struct {
	db *gorm.DB
	e  casbin.IEnforcer
}

func NewController(db *gorm.DB, modelPath string) (*Controller, error) {
	if err := db.AutoMigrate(model.Role{}); err != nil {
		return nil, err
	}
	a, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, err
	}
	e, err := casbin.NewDistributedEnforcer(modelPath, a)
	if err != nil {
		return nil, err
	}
	e.StartAutoLoadPolicy(autoLoadInterval)
	return &Controller{db: db, e: e}, nil
}

func (ctl *Controller) CheckPerm(ctx context.Context, role perm.Role, obj perm.Obj, act perm.Act) (bool, bool, bool, error) {
	return ctl.CheckPermTx(ctl.db.WithContext(ctx), role, obj, act)
}

func (ctl *Controller) CheckPermTx(db *gorm.DB, role perm.Role, obj perm.Obj, act perm.Act) (bool, bool, bool, error) {
	dbRole := &model.Role{}
	var enable, isAdmin bool
	if err := db.Where("id = ?", role).First(dbRole).Error; err != nil {
		return false, false, false, err
	}
	enable = dbRole.Enable
	isAdmin = dbRole.IsAdmin
	if !enable {
		return false, enable, isAdmin, nil
	}
	if isAdmin {
		return true, enable, isAdmin, nil
	}
	ok, err := ctl.e.HasPolicy(role2CasbinSub(role), string(obj), string(act))
	if err != nil {
		return false, false, false, err
	}
	return ok, enable, isAdmin, nil
}

func (ctl *Controller) CheckPerms(ctx context.Context, roles []perm.Role, obj perm.Obj, act perm.Act) (bool, error) {
	return ctl.CheckPermsTx(ctl.db.WithContext(ctx), roles, obj, act)
}

func (ctl *Controller) CheckPermsTx(db *gorm.DB, roles []perm.Role, obj perm.Obj, act perm.Act) (bool, error) {
	for _, role := range roles {
		if ok, _, _, err := ctl.CheckPermTx(db, role, obj, act); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}
	return false, nil
}

func (ctl *Controller) CreateRole(ctx context.Context, role perm.Role, creator int64, name, desc string, isAdmin bool, perms ...perm.Perm) (*perm.RolePerms, error) {
	return ctl.CreateRoleTx(ctl.db.WithContext(ctx), role, creator, name, desc, isAdmin, perms...)
}

func (ctl *Controller) CreateRoleTx(db *gorm.DB, role perm.Role, creator int64, name, desc string, isAdmin bool, perms ...perm.Perm) (*perm.RolePerms, error) {
	var ret *perm.RolePerms
	dbRole := &model.Role{
		ID:      int64(role),
		Enable:  true,
		IsAdmin: isAdmin,
		Creator: creator,
		Name:    name,
		Desc:    desc,
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(dbRole).Error; err != nil {
			return err
		}
		if !isAdmin && len(perms) > 0 {
			if _, err := ctl.e.AddPolicies(perms2CasbinRules(roleID2CasbinSub(dbRole.ID), perms)); err != nil {
				return err
			}
			if rolePerm, err := ctl.toRolePerms(dbRole); err != nil {
				return err
			} else {
				ret = rolePerm
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ret, nil
}

func (ctl *Controller) UpdateRole(ctx context.Context, role perm.Role, name, desc string) error {
	return ctl.UpdateRoleTx(ctl.db.WithContext(ctx), role, name, desc)
}

func (ctl *Controller) UpdateRoleTx(db *gorm.DB, role perm.Role, name, desc string) error {
	return db.Model(&model.Role{}).Where("id = ?", role).Updates(map[string]interface{}{
		"name": name,
		"desc": desc,
	}).Error
}

func (ctl *Controller) DeleteRole(ctx context.Context, role perm.Role) error {
	return ctl.DeleteRoleTx(ctl.db.WithContext(ctx), role)
}

func (ctl *Controller) DeleteRoleTx(db *gorm.DB, role perm.Role) error {
	return db.Transaction(func(tx *gorm.DB) error {
		rules, err := ctl.e.GetPermissionsForUser(role2CasbinSub(role))
		if err != nil {
			return err
		}
		if _, err := ctl.e.RemovePolicies(rules); err != nil {
			return err
		}
		return tx.Unscoped().Where("id = ?", role).Delete(&model.Role{}).Error
	})
}

func (ctl *Controller) ListRoleInfo(ctx context.Context, name string, enable int32, offset, limit, order int64) ([]*perm.RoleInfo, int64, error) {
	return ctl.ListRoleInfoTx(ctl.db.WithContext(ctx), name, enable, offset, limit, order)
}

func (ctl *Controller) ListRoleInfoTx(db *gorm.DB, name string, enable int32, offset, limit, order int64) ([]*perm.RoleInfo, int64, error) {
	if offset < 0 || (limit <= 0 && limit != -1) {
		return nil, 0, errors.New("invalid offset or limit")
	}
	var rets []*perm.RoleInfo
	var count int64
	if err := db.Transaction(func(tx *gorm.DB) error {
		var dbRoles []*model.Role
		_tx := tx
		if name != "" {
			_tx = _tx.Where("name LIKE ?", "%"+name+"%")
		}
		if enable > 0 {
			_tx = _tx.Where("enable = ?", true)
		} else if enable < 0 {
			_tx = _tx.Where("enable = ?", false)
		}
		if order < 0 {
			_tx = _tx.Order("id desc")
		}
		if err := _tx.Model(&model.Role{}).
			Offset(int(offset)).Limit(int(limit)).Find(&dbRoles).
			Offset(-1).Limit(-1).Count(&count).Error; err != nil {
			return err
		}
		for _, dbRole := range dbRoles {
			rets = append(rets, toRoleInfo(dbRole))
		}
		return nil
	}); err != nil {
		return nil, 0, err
	}
	return rets, count, nil
}

func (ctl *Controller) GetRoleInfo(ctx context.Context, role perm.Role) (*perm.RoleInfo, error) {
	return ctl.GetRoleInfoTx(ctl.db.WithContext(ctx), role)
}

func (ctl *Controller) GetRoleInfoTx(db *gorm.DB, role perm.Role) (*perm.RoleInfo, error) {
	dbRole := &model.Role{}
	if err := db.Where("id = ?", role).First(dbRole).Error; err != nil {
		return nil, err
	}
	return toRoleInfo(dbRole), nil
}

func (ctl *Controller) GetRoleInfos(ctx context.Context, roles []perm.Role, order int64) ([]*perm.RoleInfo, error) {
	return ctl.GetRoleInfosTx(ctl.db.WithContext(ctx), roles, order)
}

func (ctl *Controller) GetRoleInfosTx(db *gorm.DB, roles []perm.Role, order int64) ([]*perm.RoleInfo, error) {
	var dbRoles []*model.Role
	if len(roles) > 0 {
		db = db.Where("id IN ?", roles)
	}
	if order < 0 {
		db = db.Order("id desc")
	}
	if err := db.Model(&model.Role{}).Find(&dbRoles).Error; err != nil {
		return nil, err
	}
	var rets []*perm.RoleInfo
	for _, dbRole := range dbRoles {
		rets = append(rets, toRoleInfo(dbRole))
	}
	return rets, nil
}

func (ctl *Controller) ListRolePerms(ctx context.Context, name string, enable int32, offset, limit, order int64) ([]*perm.RolePerms, int64, error) {
	return ctl.ListRolePermsTx(ctl.db.WithContext(ctx), name, enable, offset, limit, order)
}

func (ctl *Controller) ListRolePermsTx(db *gorm.DB, name string, enable int32, offset, limit, order int64) ([]*perm.RolePerms, int64, error) {
	if offset < 0 || limit <= 0 {
		return nil, 0, errors.New("invalid offset or limit")
	}
	var rets []*perm.RolePerms
	var count int64
	if err := db.Transaction(func(tx *gorm.DB) error {
		var roles []perm.Role
		_tx := tx
		if name != "" {
			_tx = _tx.Where("name LIKE ?", "%"+name+"%")
		}
		if enable > 0 {
			_tx = _tx.Where("enable = ?", true)
		} else if enable < 0 {
			_tx = _tx.Where("enable = ?", false)
		}
		if order < 0 {
			_tx = _tx.Order("id desc")
		}
		if err := _tx.Model(&model.Role{}).
			Offset(int(offset)).Limit(int(limit)).Pluck("id", &roles).
			Offset(-1).Limit(-1).Count(&count).Error; err != nil {
			return err
		}
		for _, role := range roles {
			if ret, err := ctl.GetRolePermsTx(tx, role); err != nil {
				return err
			} else {
				rets = append(rets, ret)
			}
		}
		return nil
	}); err != nil {
		return nil, 0, err
	}
	return rets, count, nil
}

func (ctl *Controller) GetRolePerms(ctx context.Context, role perm.Role) (*perm.RolePerms, error) {
	return ctl.GetRolePermsTx(ctl.db.WithContext(ctx), role)
}

func (ctl *Controller) GetRolePermsTx(db *gorm.DB, role perm.Role) (*perm.RolePerms, error) {
	dbRole := &model.Role{}
	if err := db.Where("id = ?", role).First(dbRole).Error; err != nil {
		return nil, err
	}
	return ctl.toRolePerms(dbRole)
}

func (ctl *Controller) GrantRolePerms(ctx context.Context, role perm.Role, perms []perm.Perm) error {
	return ctl.GrantRolePermsTx(ctl.db.WithContext(ctx), role, perms)
}

func (ctl *Controller) GrantRolePermsTx(db *gorm.DB, role perm.Role, perms []perm.Perm) error {
	if len(perms) == 0 {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", role).First(&model.Role{}).Error; err != nil {
			return err
		}
		if _, err := ctl.e.AddPoliciesEx(perms2CasbinRules(role2CasbinSub(role), perms)); err != nil {
			return err
		}
		return nil
	})
}

func (ctl *Controller) RevokeRolePerms(ctx context.Context, role perm.Role, perms []perm.Perm) error {
	return ctl.RevokeRolePermsTx(ctl.db.WithContext(ctx), role, perms)
}

func (ctl *Controller) RevokeRolePermsTx(db *gorm.DB, role perm.Role, perms []perm.Perm) error {
	if len(perms) == 0 {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", role).First(&model.Role{}).Error; err != nil {
			return err
		}
		if _, err := ctl.e.RemovePolicies(perms2CasbinRules(role2CasbinSub(role), perms)); err != nil {
			return err
		}
		return nil
	})
}

func (ctl *Controller) CleanRolePerms(ctx context.Context, role perm.Role) error {
	return ctl.CleanRolePermsTx(ctl.db.WithContext(ctx), role)
}

func (ctl *Controller) CleanRolePermsTx(db *gorm.DB, role perm.Role) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", role).First(&model.Role{}).Error; err != nil {
			return err
		}
		if err := ctl.e.LoadPolicy(); err != nil {
			// db同步一下policy
			return err
		}
		rules, err := ctl.e.GetPermissionsForUser(role2CasbinSub(role))
		if err != nil {
			return err
		}
		if _, err := ctl.e.RemovePolicies(rules); err != nil {
			return err
		}
		return nil
	})
}

func (ctl *Controller) EnableRole(ctx context.Context, role perm.Role) error {
	return ctl.EnableRoleTx(ctl.db.WithContext(ctx), role)
}

func (ctl *Controller) EnableRoleTx(db *gorm.DB, role perm.Role) error {
	return db.Model(&model.Role{}).Where("id = ?", role).Updates(map[string]interface{}{
		"enable": true,
	}).Error
}

func (ctl *Controller) DisableRole(ctx context.Context, role perm.Role) error {
	return ctl.DisableRoleTx(ctl.db.WithContext(ctx), role)
}

func (ctl *Controller) DisableRoleTx(db *gorm.DB, role perm.Role) error {
	return db.Model(&model.Role{}).Where("id = ?", role).Updates(map[string]interface{}{
		"enable": false,
	}).Error
}

// --- internal method ---

func (ctl *Controller) toRolePerms(dbRole *model.Role) (*perm.RolePerms, error) {
	rules, err := ctl.e.GetPermissionsForUser(roleID2CasbinSub(dbRole.ID))
	if err != nil {
		return nil, err
	}
	return &perm.RolePerms{
		CreatedAt: dbRole.CreatedAt,
		Role:      perm.Role(dbRole.ID),
		Enable:    dbRole.Enable,
		IsAdmin:   dbRole.IsAdmin,
		Creator:   dbRole.Creator,
		Name:      dbRole.Name,
		Desc:      dbRole.Desc,
		Perms:     casbinRules2Perms(rules),
	}, nil
}

// --- internal function ---

func toRoleInfo(dbRole *model.Role) *perm.RoleInfo {
	return &perm.RoleInfo{
		CreatedAt: dbRole.CreatedAt,
		Role:      perm.Role(dbRole.ID),
		Enable:    dbRole.Enable,
		IsAdmin:   dbRole.IsAdmin,
		Creator:   dbRole.Creator,
		Name:      dbRole.Name,
		Desc:      dbRole.Desc,
	}
}

func roleID2CasbinSub(roleID int64) string {
	return strconv.Itoa(int(roleID))
}

func role2CasbinSub(role perm.Role) string {
	return strconv.Itoa(int(role))
}

// []perm.Perm -> [][]string{{sub, obj, act}}
func perms2CasbinRules(sub string, perms []perm.Perm) [][]string {
	var ps [][]string
	for _, p := range perms {
		ps = append(ps, []string{sub, string(p.Obj), string(p.Act)})
	}
	return ps
}

// [][]string{{sub, obj, act}} -> []perm.Perm
func casbinRules2Perms(ps [][]string) []perm.Perm {
	var perms []perm.Perm
	for _, p := range ps {
		if len(p) == 3 {
			perms = append(perms, perm.Perm{
				Obj: perm.Obj(p[1]),
				Act: perm.Act(p[2]),
			})
		}
	}
	return perms
}
