package tables

import (
	"time"

	"gorm.io/gorm"
)

type Vault struct {
	ID          int    `gorm:"column:vault_id;primaryKey;autoIncrement"`
	PID         string `gorm:"column:vault_pid;unique;type:varchar(100)"`
	Name        string `gorm:"column:vault_name;not null;type:varchar(100)"`
	Description string `gorm:"column:vault_description;not null;type:varchar(20000)"`
	PublicKey   []byte `gorm:"column:public_key;not null"`
	IsPersonal  bool   `gorm:"column:is_personal;not null;default:false"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type VaultCredentials struct {
	ID           int `gorm:"column:vault_credential_id;primaryKey;autoIncrement"`
	VaultID      int `gorm:"column:vault_id;not null"`
	CredentialID int `gorm:"column:credential_id;not null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (t *Vault) TableName() string {
	return "vault"
}

func (t *VaultCredentials) TableName() string {
	return "vault_credentials"
}

// Create a new vault
func (db *DB) CreateVault(vault Vault, userPID string) error {
	user := Users{}
	err := db.gormDB.Where("user_pid = ?", userPID).First(&user).Error
	if err != nil {
		return err
	}
	if vault.PID == "" {
		vault.PID = UUIDWithPrefix("vault")
	}
	vaultCreateTx := db.gormDB.Create(&vault)
	if vaultCreateTx.Error != nil {
		vaultCreateTx.Rollback()
		return vaultCreateTx.Error
	}

	permissionAssignmentCreateTx := db.gormDB.Create(&PermissionAssignments{
		PermissionName: OwnerPermission,
		PID:            UUIDWithPrefix("permissionassignment"),
		VaultID:        vault.ID,
		UserID:         user.ID,
		ResourcePID:    vault.PID,
		ResourceType:   VaultResource,
		IdentityPID:    userPID,
		IdentityType:   UserIdentity,
	})
	if permissionAssignmentCreateTx.Error != nil {
		permissionAssignmentCreateTx.Rollback()
		vaultCreateTx.Rollback()
		return permissionAssignmentCreateTx.Error
	}
	return nil
}

func (db *DB) EditVault(vaultID int, vaultContent Vault) *gorm.DB {
	return db.gormDB.Model(&Vault{}).Where("vault_id = ?", vaultID).Updates(vaultContent)
}

// Delete a vault
func (db *DB) DeleteVault(vaultID int) error {
	txns := []*gorm.DB{}
	vaultCredentials := []*VaultCredentials{}
	err := db.gormDB.Where("vault_id = ?", vaultID).Find(&vaultCredentials).Error
	if err != nil {
		return err
	}
	// delete all credential data that is in the vault
	for _, vaultCredential := range vaultCredentials {
		tx := db.gormDB.Where("credential_id = ?", vaultCredential.CredentialID).Delete(&Credential{})
		if tx.Error != nil {
			db.RollbackTxns(txns)
			return tx.Error
		}
		txns = append(txns, tx)
	}

	vaultCredentialDeleteTx := db.gormDB.Where("vault_id = ?", vaultID).Delete(&VaultCredentials{})
	if vaultCredentialDeleteTx.Error != nil {
		db.RollbackTxns(txns)
		return vaultCredentialDeleteTx.Error
	}
	txns = append(txns, vaultCredentialDeleteTx)

	vaultDeleteTx := db.gormDB.Where("vault_id = ?", vaultID).Delete(&Vault{})
	if vaultDeleteTx.Error != nil {
		db.RollbackTxns(txns)
		return vaultDeleteTx.Error
	}
	txns = append(txns, vaultDeleteTx)
	// delete all permissionassignments
	permissionAssignmentDeleteTx := db.gormDB.Where("vault_id = ?", vaultID).Delete(&PermissionAssignments{})
	if permissionAssignmentDeleteTx.Error != nil {
		db.RollbackTxns(txns)
		return permissionAssignmentDeleteTx.Error
	}
	return nil
}

// Get a vault by id
func (db *DB) GetVaultByID(id int) (*Vault, error) {
	var vault Vault
	err := db.gormDB.Where("id = ?", id).First(&vault).Error
	return &vault, err
}

func (db *DB) GetVaultByPID(pid string) (*Vault, error) {
	var vault Vault
	err := db.gormDB.Where("vault_pid = ?", pid).First(&vault).Error
	return &vault, err
}

func (db *DB) GetUserPersonalVaultByUserPID(userPID string) (*Vault, error) {
	var vault Vault
	err := db.gormDB.Where("is_personal = ? AND vault_name = ?", true, userPID).First(&vault).Error
	return &vault, err
}

// create a new vault - credential mapping
func (db *DB) CreateVaultCredential(vault_credential *VaultCredentials) error {
	return db.gormDB.Create(vault_credential).Error
}

// Get a vault - credential mapping by id
func (db *DB) GetVaultCredentialByID(id int) (*VaultCredentials, error) {
	var vault_credential VaultCredentials
	err := db.gormDB.Where("id = ?", id).First(&vault_credential).Error
	return &vault_credential, err
}

func (db *DB) AddCredentialToVault(credentialID int, vaultID int) *gorm.DB {
	return db.gormDB.Create(&VaultCredentials{
		VaultID:      vaultID,
		CredentialID: credentialID,
	})
}

func (db *DB) GetCredentialsForVault(vaultID int) ([]*Credential, error) {
	var vaultCredentials []*VaultCredentials
	err := db.gormDB.Where("vault_id = ?", vaultID).Find(&vaultCredentials).Error
	var credentials []*Credential
	for _, vaultCredential := range vaultCredentials {
		credential, err := db.GetCredentialByID(vaultCredential.CredentialID)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, err
}

func (db *DB) GetVaultIDForCredential(credentialID int) (*VaultCredentials, error) {
	var vaultCredentials VaultCredentials
	err := db.gormDB.Where("credential_id = ?", credentialID).First(&vaultCredentials).Error
	if err != nil {
		return nil, err
	}
	return &vaultCredentials, nil
}

func (db *DB) GetVaultsForUser(userPID string) ([]Vault, error) {
	var vaults []Vault
	var permissionAssignments []*PermissionAssignments
	err := db.gormDB.Where("resource_type = ? AND identity_pid = ?", VaultResource, userPID).Find(&permissionAssignments).Error
	if err != nil {
		return nil, err
	}

	// empty struct is a zero size structure, so we can safely use it as a dummy value field in a map
	vaultIDList := make(map[int]struct{})

	for _, permissionAssignment := range permissionAssignments {
		_, ok := vaultIDList[permissionAssignment.VaultID]
		if !ok {
			vault, err := db.GetVaultByID(permissionAssignment.VaultID)
			if err != nil {
				return nil, err
			}
			vaults = append(vaults, *vault)
			vaultIDList[permissionAssignment.VaultID] = struct{}{}
		}
	}

	return vaults, nil
}
