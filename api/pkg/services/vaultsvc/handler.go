package vaultsvc

import (
	"context"

	"github.com/GDGVIT/configgy-backend/api/pkg/services/accesscontrolsvc"
	"github.com/GDGVIT/configgy-backend/pkg/logger"
	"github.com/GDGVIT/configgy-backend/pkg/tables"
	"gorm.io/gorm"
)

type VaultServiceImpl struct {
	DB                VaultDb
	logger            logger.Logger
	messageBroker     MessageBroker
	accesscontrolrsvc AccessControlSvc
	authnsvc          AuthnSvc
}

type AccessControlSvc interface {
	CreatePermissionAssignment(permission_assignment *tables.PermissionAssignments) *gorm.DB
	UserHasPermissionToResource(userID int, resourceID int, resourceType tables.ResourceTypes, action accesscontrolsvc.CRUDOperation) (bool, error)
}

type AuthnSvc interface {
	ValidateToken(signedToken string) error
}

type VaultDb interface {
	CreateVault(vault tables.Vault, userPID string) error
	EditVault(vaultID int, vaultContent tables.Vault) *gorm.DB
	DeleteVault(vaultID int) error
	GetVaultByID(id int) (*tables.Vault, error)
	GetVaultByPID(pid string) (*tables.Vault, error)
	CreateVaultCredential(vault_credential *tables.VaultCredentials) error
	GetVaultCredentialByID(id int) (*tables.VaultCredentials, error)
	GetUserByPID(pid string) (*tables.Users, error)

	GetVaultsForUser(userPID string) ([]tables.Vault, error)
}

type MessageBroker interface {
	Publish(ctx context.Context, exchange, routingKey string, body []byte) error
}

func Handler(vaultDb VaultDb, logger logger.Logger, messageBroker MessageBroker, accesscontrolrSvc AccessControlSvc, authnSvc AuthnSvc) *VaultServiceImpl {
	return &VaultServiceImpl{
		DB:                vaultDb,
		logger:            logger,
		messageBroker:     messageBroker,
		accesscontrolrsvc: accesscontrolrSvc,
		authnsvc:          authnSvc,
	}
}
