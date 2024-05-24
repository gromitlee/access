package model

// Role 角色 DB model
type Role struct {
	ID        int64 `gorm:"primary_key"`
	CreatedAt int64 `gorm:"autoCreateTime:milli;not null"`
	UpdatedAt int64 `gorm:"autoUpdateTime:milli;not null"`
	// 是否启用
	Enable bool `gorm:"index:idx_role_enable;not null"`
	// 是否admin
	IsAdmin bool `gorm:"index:idx_role_is_admin;not null"`
	// 创建用户id（考虑到用户可以被删除，因此不做外键关联）
	Creator int64 `gorm:"not null"`
	// 角色名
	Name string `gorm:"index:idx_role_name;unique;not null"`
	// 角色描述
	Desc string `gorm:"not null"`
}
