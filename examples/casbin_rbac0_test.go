package examples

import (
	"testing"

	"github.com/gromitlee/access"
)

func TestCasbinRBAC0Controller(t *testing.T) {
	db := getDB(dbMysql, dbName)
	if err := access.InitCasbinRBAC0Controller(db, "casbin_rbac0_model.conf"); err != nil {
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
