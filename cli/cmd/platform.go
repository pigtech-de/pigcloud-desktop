package cmd

import (
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/config"
	"pigcloud/internal/keyringstore"
)

func init() {
	config.SetSecretStore(keyringstore.New())
	cmdutil.InstallKeySeam()
}
