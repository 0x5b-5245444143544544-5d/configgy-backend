package vaultsvc

import (
	"context"

	"github.com/GDGVIT/configgy-backend/api/pkg/api"
	"github.com/GDGVIT/configgy-backend/api/pkg/services/accesscontrolsvc"
	"github.com/GDGVIT/configgy-backend/pkg/tables"
)

func (svc *VaultServiceImpl) VaultGet(c context.Context, vaultPID string, userPID string) (api.VaultWithCredentials, int, error) {
	res := api.VaultWithCredentials{}
	credentialList := make([]api.CredentialStub, 0)
	user, err := svc.DB.GetUserByPID(userPID)
	if err != nil {
		return res, 0, err
	}
	vault, err := svc.DB.GetVaultByPID(vaultPID)
	if err != nil {
		return res, 0, err
	}
	permission, err := svc.accesscontrolrsvc.UserHasPermissionToResource(user.ID, vault.ID, tables.VaultResource, accesscontrolsvc.ReadOperation)
	if err != nil {
		return res, 0, err
	}
	if !permission {
		return res, 0, nil
	}
	credentials, err := svc.DB.GetCredentialsForVault(vault.ID)
	if err != nil {
		return res, 0, err
	}
	for _, credential := range credentials {
		permission, err := svc.accesscontrolrsvc.UserHasPermissionToResource(user.ID, credential.CredentialID, tables.CredentialResource, accesscontrolsvc.ReadOperation)
		if err != nil {
			return res, 0, err
		}
		if !permission {
			continue
		}
		credentialList = append(credentialList, api.CredentialStub{
			Pid:            credential.PID,
			Name:           credential.CredentialName,
			CredentialType: api.CredentialStubCredentialType(credential.CredentialType),
		})
	}

	res.Name = vault.Name
	res.Pid = vault.PID
	res.Description = &vault.Description
	res.PublicKey = string(vault.PublicKey)
	res.Credentials = credentialList

	return res, 0, nil
}
