package vaultsvc

import (
	"context"

	"github.com/GDGVIT/configgy-backend/api/pkg/api"
	"github.com/GDGVIT/configgy-backend/api/pkg/services/accesscontrolsvc"
	"github.com/GDGVIT/configgy-backend/pkg/tables"
)

func (svc *VaultServiceImpl) VaultEdit(c context.Context, vaultPID string, vaultContent api.VaultEditRequest, userPID string) (api.GenericMessageResponse, int, error) {
	user, err := svc.DB.GetUserByPID(userPID)
	if err != nil {
		return api.GenericMessageResponse{}, 0, err
	}
	vault, err := svc.DB.GetVaultByPID(vaultPID)
	if err != nil {
		return api.GenericMessageResponse{}, 0, err
	}
	hasPermission, err := svc.accesscontrolrsvc.UserHasPermissionToResource(user.ID, vault.ID, tables.VaultResource, accesscontrolsvc.UpdateOperation)
	if err != nil {
		return api.GenericMessageResponse{}, 0, err
	}
	if !hasPermission {
		message := "User does not have permission to edit this vault"
		return api.GenericMessageResponse{Message: &message}, 0, nil
	}
	if vaultContent.Name != nil {
		vault.Name = *vaultContent.Name
	}
	if vaultContent.Description != nil {
		vault.Description = *vaultContent.Description
	}
	if vaultContent.PublicKey != nil {
		vault.PublicKey = []byte(*vaultContent.PublicKey)
	}
	// edit the vault
	tx := svc.DB.EditVault(vault.ID, *vault)
	err = tx.Error
	if err != nil {
		tx.Rollback()
		return api.GenericMessageResponse{}, 0, err
	}
	return api.GenericMessageResponse{}, 0, nil
}
