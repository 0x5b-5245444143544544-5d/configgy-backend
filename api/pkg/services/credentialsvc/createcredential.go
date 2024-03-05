package credentialsvc

import (
	"context"
	"errors"
	"os"

	"github.com/GDGVIT/configgy-backend/api/pkg/api"
	"github.com/GDGVIT/configgy-backend/api/pkg/services/accesscontrolsvc"
	"github.com/GDGVIT/configgy-backend/config"
	"github.com/GDGVIT/configgy-backend/pkg/crypto"
	"github.com/GDGVIT/configgy-backend/pkg/tables"
	"gorm.io/gorm"
)

func (svc *CredentialServiceImpl) CredentialCreate(c context.Context, req api.CredentialCreateRequest, userPID string) (api.GenericMessageResponse, int, error) {
	var credentialID int
	var createActualCredentialTx *gorm.DB
	var err error

	switch req.CredentialType {
	case api.CredentialCreateRequestCredentialTypePassword:
		credentialID, createActualCredentialTx, err = svc.createPasswordCredential(c, req, userPID)
	case api.CredentialCreateRequestCredentialTypeFeatureFlags:
		credentialID, createActualCredentialTx, err = svc.createFeatureFlagsCredential(c, req, userPID)
	case api.CredentialCreateRequestCredentialTypeFile:
		credentialID, createActualCredentialTx, err = svc.createFileCredential(c, req, userPID)
	default:
		return api.GenericMessageResponse{}, 0, errors.New("invalid credential type")
	}
	if err != nil {
		// rollback all tx
		return api.GenericMessageResponse{}, 0, err
	}

	user, err := svc.DB.GetUserByPID(userPID)
	if err != nil {
		return api.GenericMessageResponse{}, 0, err
	}

	credentialEntry := tables.Credential{
		CredentialName: req.Name,
		Notes:          *req.Notes,
		CredentialType: tables.CredentialType(req.CredentialType),
		CredentialID:   credentialID,
		PID:            tables.UUIDWithPrefix("cred"),
	}
	createCredentialTx := svc.DB.CreateCredential(&credentialEntry)
	if createCredentialTx.Error != nil {
		// rollback all tx
		return api.GenericMessageResponse{}, 0, createCredentialTx.Error
	}
	createPermissionAssignmentTx := svc.accesscontrolrsvc.CreatePermissionAssignment(&tables.PermissionAssignments{
		PermissionName: tables.OwnerPermission,
		CredentialID:   credentialEntry.ID,
		PID:            tables.UUIDWithPrefix("perm"),
		UserID:         user.ID,
		IdentityPID:    user.PID,
		IdentityType:   tables.UserIdentity,
		ResourcePID:    credentialEntry.PID,
		ResourceType:   tables.CredentialResource,
	})
	if createPermissionAssignmentTx.Error != nil {
		// rollback all tx
		createActualCredentialTx.Rollback()
		createCredentialTx.Rollback()
		createPermissionAssignmentTx.Rollback()
		return api.GenericMessageResponse{}, 0, err
	}
	if req.VaultPid != nil && *req.VaultPid != "" {
		vault, err := svc.DB.GetVaultByPID(*req.VaultPid)
		if err != nil {
			return api.GenericMessageResponse{}, 0, err
		}
		hasPerm, err := svc.accesscontrolrsvc.UserHasPermissionToResource(user.ID, vault.ID, tables.VaultResource, accesscontrolsvc.UpdateOperation)
		if err != nil {
			return api.GenericMessageResponse{}, 0, err
		}
		if !hasPerm {
			return api.GenericMessageResponse{}, 0, errors.New("user does not have permission to vault")
		}
		// deal with adding to vault here
		vaultCredentialEntryCreationTx := svc.DB.AddCredentialToVault(vault.ID, credentialEntry.ID)
		if vaultCredentialEntryCreationTx.Error != nil {
			// rollback all tx
			createActualCredentialTx.Rollback()
			createCredentialTx.Rollback()
			createPermissionAssignmentTx.Rollback()
			return api.GenericMessageResponse{}, 0, vaultCredentialEntryCreationTx.Error
		}
	}
	message := "Password Credential Created Successfully"
	return api.GenericMessageResponse{Message: &message}, 0, nil
}

func (svc *CredentialServiceImpl) createPasswordCredential(c context.Context, req api.CredentialCreateRequest, userPID string) (int, *gorm.DB, error) {
	password := req.Password
	var encryptedPassword []byte
	var err error

	if password != nil {
		passwordBytes := password.Password
		encryptedPassword, err = crypto.EncryptBytes(passwordBytes, svc.secretKey)
		if err != nil {
			return 0, nil, err
		}
	} else {
		return 0, nil, errors.New("password is required")
	}
	passwordEntry := tables.PasswordCredentials{
		Password: encryptedPassword,
		Username: req.Password.Username,
	}

	if req.Password.PasswordStrength != nil {
		passwordEntry.PasswordStrength = *req.Password.PasswordStrength
	}

	if req.Password.ExpiresAt != nil {
		passwordEntry.ExpiresAt = *req.Password.ExpiresAt
	}

	if password.Totp != nil {
		encryptedTotpSecret, err := crypto.EncryptBytes(password.Totp.TotpSecret, svc.secretKey)
		if err != nil {
			return 0, nil, err
		}
		passwordEntry.TOTPKey = encryptedTotpSecret
		passwordEntry.TOTPLength = password.Totp.TotpLength
		passwordEntry.TOTPPeriod = password.Totp.TotpPeriod

	}
	createPasswordTx := svc.DB.CreatePasswordCredential(&passwordEntry)
	if createPasswordTx.Error != nil {
		createPasswordTx.Rollback()
		return 0, createPasswordTx, createPasswordTx.Error
	}
	return passwordEntry.ID, createPasswordTx, nil

}

func (svc *CredentialServiceImpl) createFileCredential(c context.Context, req api.CredentialCreateRequest, userPID string) (int, *gorm.DB, error) {
	file := req.File
	fileStorepath := config.LoadFileStoragePath()
	var encryptedFile []byte
	var err error

	if file != nil {
		fileBytes := file.File
		encryptedFile, err = crypto.EncryptBytes(fileBytes, svc.secretKey)
		if err != nil {
			return 0, nil, err
		}
	} else {
		return 0, nil, errors.New("file is required")
	}
	// create a new file in the file store
	fileName := tables.UUIDWithPrefix("files")
	filePath := fileStorepath + "/" + fileName

	fileEntry, err := os.Create(filePath)
	if err != nil {
		return 0, nil, err
	}
	defer fileEntry.Close()

	_, err = fileEntry.Write(encryptedFile)
	if err != nil {
		return 0, nil, err
	}

	fileDBEntry := tables.FileCredentials{
		FilePath: filePath,
	}
	createFileCredentialTx := svc.DB.CreateFileCredential(&fileDBEntry)
	if createFileCredentialTx.Error != nil {
		createFileCredentialTx.Rollback()
		return 0, createFileCredentialTx, createFileCredentialTx.Error
	}
	return fileDBEntry.ID, createFileCredentialTx, nil
}

func (svc *CredentialServiceImpl) createFeatureFlagsCredential(c context.Context, req api.CredentialCreateRequest, userPID string) (int, *gorm.DB, error) {
	featureFlags := req.FeatureFlags
	if featureFlags == nil {
		return 0, nil, errors.New("feature flags are required")
	}
	featureFlagEntry := tables.FeatureFlagCredentials{
		FeatureFlagsetName: featureFlags.Name,
	}
	if featureFlags.Environment != nil {
		featureFlagEntry.FeatureFlagEnvironmentName = *featureFlags.Environment
	}
	createFeatureFlagCredentialTx := svc.DB.CreateFeatureFlagCredential(&featureFlagEntry)
	if createFeatureFlagCredentialTx.Error != nil {
		createFeatureFlagCredentialTx.Rollback()
		return 0, createFeatureFlagCredentialTx, createFeatureFlagCredentialTx.Error
	}
	featureFlagCredentialID := featureFlagEntry.ID
	featureFlagData := make([]*tables.FeatureFlagData, 0)
	for _, featureFlag := range featureFlags.FeatureFlags {
		featureFlagData = append(featureFlagData, &tables.FeatureFlagData{
			Name:                    featureFlag.Name,
			FeatureFlagCredentialID: featureFlagEntry.ID,
			FlagKey:                 featureFlag.Key,
			FlagValue:               featureFlag.Value,
		})
	}
	createFeatureFlagDataTx := svc.DB.AddMultipleFeatureFlags(featureFlagCredentialID, featureFlagData)
	if createFeatureFlagDataTx.Error != nil {
		createFeatureFlagCredentialTx.Rollback()
		createFeatureFlagDataTx.Rollback()
		return 0, createFeatureFlagCredentialTx, createFeatureFlagCredentialTx.Error
	}
	return featureFlagCredentialID, createFeatureFlagCredentialTx, nil

}
