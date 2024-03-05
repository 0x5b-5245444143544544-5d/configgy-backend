package credentialsvc

import (
	"context"
	"os"
	"path/filepath"

	"github.com/GDGVIT/configgy-backend/api/pkg/api"
	"github.com/GDGVIT/configgy-backend/api/pkg/services/accesscontrolsvc"
	"github.com/GDGVIT/configgy-backend/pkg/crypto"
	"github.com/GDGVIT/configgy-backend/pkg/tables"
)

func (svc *CredentialServiceImpl) CredentialGet(c context.Context, credentialPID string, userPID string) (api.CredentialCreateRequest, int, error) {
	credential, err := svc.DB.GetCredentialByPID(credentialPID)
	if err != nil {
		return api.CredentialCreateRequest{}, 0, err
	}
	user, err := svc.DB.GetUserByPID(userPID)
	if err != nil {
		return api.CredentialCreateRequest{}, 0, err
	}
	hasPermission, err := svc.accesscontrolrsvc.UserHasPermissionToResource(user.ID, credential.ID, tables.CredentialResource, accesscontrolsvc.ReadOperation)
	if err != nil {
		return api.CredentialCreateRequest{}, 0, err
	}
	if !hasPermission {
		return api.CredentialCreateRequest{}, 404, nil
	}
	switch credential.CredentialType {
	case tables.Password:
		passwordData, err := svc.DB.GetPasswordCredentialByID(credential.CredentialID)
		if err != nil {
			return api.CredentialCreateRequest{}, 0, err
		}
		decryptedPassword, err := crypto.DecryptBytes(passwordData.Password, svc.secretKey)
		var decryptedTOTPSecret []byte
		if err != nil {
			return api.CredentialCreateRequest{}, 0, err
		}
		if passwordData.TOTPKey != nil {
			decryptedTOTPSecret, err = crypto.DecryptBytes(passwordData.TOTPKey, svc.secretKey)
			if err != nil {
				return api.CredentialCreateRequest{}, 0, err
			}
		}
		return api.CredentialCreateRequest{
			CredentialType: api.CredentialCreateRequestCredentialTypePassword,
			Password: &api.PasswordCredential{
				ExpiresAt:        &passwordData.ExpiresAt,
				Password:         decryptedPassword,
				PasswordStrength: &passwordData.PasswordStrength,
				Username:         passwordData.Username,
				Totp: &api.TOTP{
					TotpSecret: decryptedTOTPSecret,
					TotpLength: passwordData.TOTPLength,
					TotpPeriod: passwordData.TOTPPeriod,
				},
			},
			Notes: &credential.Notes,
			Name:  credential.CredentialName,
		}, 0, nil
	case tables.FileCredential:
		fileCredentialEntry, err := svc.DB.GetFileCredentialByID(credential.CredentialID)
		if err != nil {
			return api.CredentialCreateRequest{}, 0, err
		}
		filePath := fileCredentialEntry.FilePath
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			return api.CredentialCreateRequest{}, 0, err
		}
		var fileBytes []byte
		fileBytes, err = os.ReadFile(absPath)
		if err != nil {
			return api.CredentialCreateRequest{}, 0, err
		}
		decryptedFileBytes, err := crypto.DecryptBytes(fileBytes, svc.secretKey)
		if err != nil {
			return api.CredentialCreateRequest{}, 0, err
		}
		return api.CredentialCreateRequest{
			CredentialType: api.CredentialCreateRequestCredentialTypeFile,
			File: &api.FileCredential{
				File: decryptedFileBytes,
			},
			Name:  credential.CredentialName,
			Notes: &credential.Notes,
		}, 0, nil

	case tables.FeatureFlag:
		featureFlagCredentialEntry, err := svc.DB.GetFeatureFlagCredentialByID(credential.CredentialID)
		if err != nil {
			return api.CredentialCreateRequest{}, 0, err
		}
		featureFlagCredentialData, err := svc.DB.GetFeatureFlagsByID(featureFlagCredentialEntry.ID)
		if err != nil {
			return api.CredentialCreateRequest{}, 0, err
		}
		var featureFlagData []api.FeatureFlag
		for _, featureFlag := range featureFlagCredentialData {
			featureFlagData = append(featureFlagData, api.FeatureFlag{
				Name:  featureFlag.Name,
				Key:   featureFlag.FlagKey,
				Value: featureFlag.FlagValue,
			})
		}
		return api.CredentialCreateRequest{
			CredentialType: api.CredentialCreateRequestCredentialTypeFeatureFlags,
			Name:           credential.CredentialName,
			Notes:          &credential.Notes,
			FeatureFlags: &api.FeatureFlagCredential{
				Name:         featureFlagCredentialEntry.FeatureFlagsetName,
				Environment:  &featureFlagCredentialEntry.FeatureFlagEnvironmentName,
				FeatureFlags: featureFlagData,
			},
		}, 0, nil
	}

	return api.CredentialCreateRequest{}, 0, nil
}
