package pkg

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name       string `gorm:"not null"`
	Email      string `gorm:"unique,not null"`
	Username   string `gorm:"unique,not null"`
	Password   string `gorm:"not null"`
	TOTPSecret string
	BaseRole   BaseRole `gorm:"not null"`
}

type BaseRole struct {
	gorm.Model
	Name        string       `gorm:"unique,not null"`
	Permissions []Permission `gorm:"many2many:base_role_permissions;"`
}

type Permission struct {
	gorm.Model
	PermissionName string `gorm:"unique,not null"`
}

type Group struct {
	gorm.Model
	GroupName string `gorm:"not null"`
	Users     []User `gorm:"many2many:group_users;"`
}

type PermissionAssignments struct {
	gorm.Model
	User       User
	Group      Group
	Credential Credential
	Vault      Vault
	Permission Permission `gorm:"many2many:permission_assignments;"`
}

type Credential struct {
	gorm.Model
	Name                  string `gorm:"not null"`
	Owner                 User   `gorm:"not null"`
	PasswordCredential    PasswordCredential
	FileCredential        []FileCredential
	FeatureFlagCredential []FeatureFlagCredential
	Vault                 Vault
}

type Vault struct {
	gorm.Model
	Name       string `gorm:"not null"`
	Owner      User   `gorm:"not null"`
	Encryption Encryption
}

type Encryption struct {
	gorm.Model
	Password        string
	KeyPath         string
	RotationEnabled bool
}

type PasswordCredential struct {
	gorm.Model
	Username        string `gorm:"not null"`
	Password        string `gorm:"not null"`
	ExpiryDate      time.Time
	TOTPSecret      TOTPSecret
	RotationEnabled bool
	Notes           string
	Strength        int
}

type TOTPSecret struct {
	gorm.Model
	Secret string `gorm:"not null"`
	Digits int    `gorm:"default:6,not null"`
	Period int    `gorm:"default:30,not null"`
}

type FileCredential struct {
	gorm.Model
	FilePath string `gorm:"not null"`
	Notes    string
}

type FeatureFlagCredential struct {
	gorm.Model
	Name         string        `gorm:"not null"`
	FeatureFlags []FeatureFlag `gorm:"not null"`
	Notes        string
}

type FeatureFlag struct {
	gorm.Model
	Name  string
	Key   string `gorm:"not null"`
	Value string `gorm:"not null"`
}
