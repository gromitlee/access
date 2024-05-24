package examples

import (
	"errors"
	"testing"

	"github.com/gromitlee/access"
	"github.com/gromitlee/access/pkg/perm"
	"gorm.io/gorm"
)

const (
	roleSysAdmin    perm.Role = 1
	roleTenantAdmin perm.Role = 2
	roleTenantUser  perm.Role = 3
	roleSysUser     perm.Role = 4

	objSystem  = "obj_system"
	objTenant  = "obj_tenant"
	objProject = "obj_project"

	act = "act"
)

func TestAccessRBAC0Controller(t *testing.T) {
	db := getDB(dbMysql, dbName)
	if err := access.InitAccessRBAC0Controller(db); err != nil {
		t.Fatal(err)
	}
	if err := createRolesAndAddPerms(db); err != nil {
		t.Fatal(err)
	}
	if err := checkTenantAdminPerms(db); err != nil {
		t.Fatal(err)
	}
	if err := deleteRoles(db); err != nil {
		t.Fatal(err)
	}
}

func createRolesAndAddPerms(db *gorm.DB) error {
	// role: sys_admin
	if _, err := access.RBAC0CreateRole(db, roleSysAdmin, 0, "role_sys_admin", "", true); err != nil {
		return err
	}
	if sysAdmin, err := access.RBAC0GetRoleInfo(db, roleSysAdmin); err != nil {
		return err
	} else if sysAdmin.Role != roleSysAdmin {
		return errors.New("unexpected role")
	}
	// role: tenant_admin
	if _, err := access.RBAC0CreateRole(db, roleTenantAdmin, 0, "role_tenant_admin", "", false); err != nil {
		return err
	}
	if tenantAdmin, err := access.RBAC0GetRoleInfo(db, roleTenantAdmin); err != nil {
		return err
	} else if tenantAdmin.Role != roleTenantAdmin {
		return errors.New("unexpected role")
	}
	// role: tenant_user
	if _, err := access.RBAC0CreateRole(db, roleTenantUser, 0, "role_tenant_user", "", false); err != nil {
		return err
	}
	if tenantUser, err := access.RBAC0GetRoleInfo(db, roleTenantUser); err != nil {
		return err
	} else if tenantUser.Role != roleTenantUser {
		return errors.New("unexpected role")
	}
	// role: sys_user
	if _, err := access.RBAC0CreateRole(db, roleSysUser, 0, "role_sys_user", "", false); err != nil {
		return err
	}
	if sysUser, err := access.RBAC0GetRoleInfo(db, roleSysUser); err != nil {
		return err
	} else if sysUser.Role != roleSysUser {
		return errors.New("unexpected role")
	}

	// get infos
	if roles, err := access.RBAC0GetRoleInfos(db, []perm.Role{roleSysAdmin, roleTenantAdmin, roleTenantUser, roleSysUser}, -1); err != nil {
		return err
	} else if len(roles) != 4 {
		return errors.New("unexpected count")
	}

	// sys_admin -> obj_system/obj_tenant/obj_project
	if err := access.RBAC0GrantRolePerms(db, roleSysAdmin, []perm.Perm{
		{Obj: objSystem, Act: act}, {Obj: objTenant, Act: act}, {Obj: objProject, Act: act},
	}); err != nil {
		return err
	}

	// tenant_admin -> obj_tenant/obj_project
	if err := access.RBAC0GrantRolePerms(db, roleTenantAdmin, []perm.Perm{
		{Obj: objTenant, Act: act}, {Obj: objProject, Act: act},
	}); err != nil {
		return err
	}

	// tenant_user -> obj_project
	if err := access.RBAC0GrantRolePerms(db, roleTenantUser, []perm.Perm{
		{Obj: objProject, Act: act},
	}); err != nil {
		return err
	}

	return nil
}

func checkTenantAdminPerms(db *gorm.DB) error {
	// list infos
	if _, count, err := access.RBAC0ListRoleInfo(db, "tenant", 1, 0, 10, -1); err != nil {
		return err
	} else if count != 2 {
		return errors.New("unexpected count")
	}

	// list perms
	if _, count, err := access.RBAC0ListRolePerms(db, "tenant", 1, 0, 10, -1); err != nil {
		return err
	} else if count != 2 {
		return errors.New("unexpected count")
	}

	// check perms
	if ok, _, _, err := access.RBAC0CheckPerm(db, roleTenantAdmin, objSystem, act); err != nil {
		return err
	} else if ok {
		return errors.New("unexpected permission")
	}
	if ok, _, _, err := access.RBAC0CheckPerm(db, roleTenantAdmin, objTenant, act); err != nil {
		return err
	} else if !ok {
		return errors.New("no permission")
	}
	if ok, _, _, err := access.RBAC0CheckPerm(db, roleTenantAdmin, objProject, act); err != nil {
		return err
	} else if !ok {
		return errors.New("no permission")
	}

	// enable & disable role
	if err := access.RBAC0DisableRole(db, roleTenantAdmin); err != nil {
		return err
	}
	if ok, _, _, err := access.RBAC0CheckPerm(db, roleTenantAdmin, objTenant, act); err != nil {
		return err
	} else if ok {
		return errors.New("no permission")
	}
	if err := access.RBAC0EnableRole(db, roleTenantAdmin); err != nil {
		return err
	}

	// clean role
	if err := access.RBAC0CleanRolePerms(db, roleTenantAdmin); err != nil {
		return err
	}
	if tenantAdmin, err := access.RBAC0GetRolePerms(db, roleTenantAdmin); err != nil {
		return err
	} else if len(tenantAdmin.Perms) > 0 {
		return errors.New("unexpected permission")
	}

	// grant & revoke perms
	if err := access.RBAC0GrantRolePerms(db, roleTenantAdmin, []perm.Perm{
		{Obj: objSystem, Act: act}, {Obj: objTenant, Act: act}, {Obj: objProject, Act: act},
	}); err != nil {
		return err
	}
	if ok, _, _, err := access.RBAC0CheckPerm(db, roleTenantAdmin, objSystem, act); err != nil {
		return err
	} else if !ok {
		return errors.New("no permission")
	}
	if err := access.RBAC0RevokeRolePerms(db, roleTenantAdmin, []perm.Perm{
		{Obj: objSystem, Act: act},
	}); err != nil {
		return err
	}
	if ok, _, _, err := access.RBAC0CheckPerm(db, roleTenantAdmin, objSystem, act); err != nil {
		return err
	} else if ok {
		return errors.New("unexpected permission")
	}

	// delete role
	if err := access.RBAC0DeleteRole(db, roleTenantAdmin); err != nil {
		return err
	}
	if _, err := access.RBAC0GetRolePerms(db, roleTenantAdmin); err != nil {
		if err != gorm.ErrRecordNotFound {
			return err
		}
	} else {
		return errors.New("unexpected role")
	}

	return nil
}

func deleteRoles(db *gorm.DB) error {
	if err := access.RBAC0DeleteRole(db, roleSysAdmin); err != nil {
		return err
	}
	if err := access.RBAC0DeleteRole(db, roleTenantAdmin); err != nil {
		return err
	}
	if err := access.RBAC0DeleteRole(db, roleTenantUser); err != nil {
		return err
	}
	if err := access.RBAC0DeleteRole(db, roleSysUser); err != nil {
		return err
	}
	return nil
}
