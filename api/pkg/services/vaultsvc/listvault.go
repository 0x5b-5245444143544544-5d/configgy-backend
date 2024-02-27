package vaultsvc

import (
	"context"

	"github.com/GDGVIT/configgy-backend/api/pkg/api"
)

func (svc *VaultServiceImpl) VaultList(c context.Context, userPID string) (api.VaultListResponse, int, error) {
	// get all the vaults the user has access to
	vaults, err := svc.DB.GetVaultsForUser(userPID)
	if err != nil {
		return nil, 0, err
	}

	response := make(api.VaultListResponse, len(vaults))

	for _, vault := range vaults {
		response = append(response, api.Vault{
			Pid:         vault.PID,
			Name:        vault.Name,
			Description: &vault.Description,
			PublicKey:   string(vault.PublicKey),
		})
	}
	return response, 200, nil
}
