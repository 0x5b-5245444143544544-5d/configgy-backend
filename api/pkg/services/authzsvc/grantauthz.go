package authzsvc

import (
	"context"
	"errors"

	"github.com/GDGVIT/configgy-backend/api/pkg/api"
	"github.com/GDGVIT/configgy-backend/api/pkg/services/accesscontrolsvc"
	"github.com/GDGVIT/configgy-backend/pkg/tables"
	"gorm.io/gorm"
)

func (svc *AuthzSvcImpl) AuthzCreate(ctx context.Context, req api.AuthzCreateRequest, userPID string) (api.GenericMessageResponse, int, error) {
	user, err := svc.DB.GetUserByPID(userPID)
	txns := []*gorm.DB{}
	if err != nil {
		return api.GenericMessageResponse{}, 0, err
	}
	for _, authz := range req {
		var resourceID int
		switch authz.ResourceType {
		case api.AuthzPermissionResourceTypeVault:
			vault, err := svc.DB.GetVaultByPID(authz.ResourcePid)
			if err != nil {
				return api.GenericMessageResponse{}, 0, err
			}
			resourceID = vault.ID
		case api.AuthzPermissionResourceTypeGroup:
			group, err := svc.DB.GetGroupByPID(authz.ResourcePid)
			if err != nil {
				return api.GenericMessageResponse{}, 0, err
			}
			resourceID = group.ID
		case api.AuthzPermissionResourceTypeCredential:
			credential, err := svc.DB.GetCredentialByPID(authz.ResourcePid)
			if err != nil {
				return api.GenericMessageResponse{}, 0, err
			}
			resourceID = credential.CredentialID
		default:
			return api.GenericMessageResponse{}, 0, errors.New("invalid resource type")
		}
		permission, err := svc.accessControlSvc.UserHasPermissionToResource(user.ID, resourceID, tables.ResourceTypes(authz.ResourceType), accesscontrolsvc.UpdateOperation)
		if err != nil {
			return api.GenericMessageResponse{}, 0, err
		}
		if !permission {
			return api.GenericMessageResponse{}, 0, errors.New("user does not have permission to update this resource")
		}
		permissionAssignment := tables.PermissionAssignments{
			PermissionName: tables.Permission(authz.AccessLevel),
			CredentialID:   resourceID,
			UserID:         user.ID,
			ResourcePID:    authz.ResourcePid,
			ResourceType:   tables.ResourceTypes(authz.ResourceType),
			IdentityPID:    authz.IdentityPid,
			IdentityType:   tables.IdentityType(authz.IdentityType),
		}

		tx := svc.DB.CreatePermissionAssignment(&permissionAssignment)
		if tx.Error != nil {
			svc.DB.RollbackTxns(txns)
		}
		txns = append(txns, tx)
		// add the encrypted keys for each user to personal vaults
		if authz.AuthorizedKeys != nil {
			secretKeys := *authz.AuthorizedKeys
			for _, keySet := range secretKeys {
				// get the user's personal vault
				userPersonalVault, err := svc.DB.GetUserPersonalVaultByUserPID(keySet.IdentityPid)
				if err != nil {
					svc.DB.RollbackTxns(txns)
					return api.GenericMessageResponse{}, 0, err
				}
				credCreationReq := api.CredentialCreateRequest{
					Name:           authz.ResourcePid,
					CredentialType: api.CredentialCreateRequestCredentialTypeFile,
					File: &api.FileCredential{
						File: []byte(keySet.EncryptedKey),
						Name: "Encrypted key for " + authz.ResourcePid,
					},
					VaultPid: &userPersonalVault.PID,
				}
				_, _, err = svc.credentialSvc.CredentialCreate(ctx, credCreationReq, keySet.IdentityPid)
				if err != nil {
					svc.DB.RollbackTxns(txns)
					return api.GenericMessageResponse{}, 0, err
				}
			}
		}
		// if the secret key isn't added to the vault, we're assuming it was shared directly somehow
	}

	return api.GenericMessageResponse{}, 0, nil
}
