# access

Go Role Based Access Control (RBAC0)

- [x] 设计实现符合RBAC定义
- [x] 支持完全由用户自定义的角色(`Role`)、权限(`Perm`)；其中权限由资源(`Obj`)和操作(`Act`)组成
- [x] 同一套API提供两种实现方式：access自身对RBAC的实现与封装[casbin](https://github.com/casbin/casbin)的实现
- [x] 提供两种使用方式：全局单例方式与管理器方式
- [x] 提供基于[gorm](https://github.com/go-gorm/gorm)的数据存储
- [x] Goroutine Safe & Developer Friendly

## 安装

```bash
go get github.com/gromitlee/access
```

## 引入

```go
import "github.com/gromitlee/access"
```

## 使用方式1：全局单例
API详见[rbac0_api.go](rbac0_api.go)

### access实现
示例详见[examples/access_rbac0_test.go](examples/access_rbac0_test.go)

```go
access.InitAccessRBAC0Controller(db)
```

### casbin实现
示例详见[examples/casbin_rbac0_test.go](examples/casbin_rbac0_test.go)

```go
access.InitCasbinRBAC0Controller(db, modelFilePath)
```

## 使用方式2：管理器
API详见[rbac0_controller.go](rbac0_controller.go)

### access实现
示例同上

```go
ctl, err := access.NewAccessRBAC0Controller(db)
```

### casbin实现
示例同上

```go
ctl, err := access.NewCasbinRBAC0Controller(db, modelFilePath)
```