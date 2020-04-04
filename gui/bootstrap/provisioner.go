package bootstrap

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// provision provisions the resources as well as the custom provision
func provision(baseDirectoryPath string, fnA RestoreAssets, fnP CustomProvision) (err error) {
	// Provision resources
	// TODO Handle upgrades and therefore removing the resources folder accordingly
	var pr = filepath.Join(baseDirectoryPath, "resources")
	if _, err = os.Stat(pr); os.IsNotExist(err) {
		// Restore assets
		logrus.Debugf("Restoring assets in %s", baseDirectoryPath)
		if err = fnA(baseDirectoryPath, "resources"); err != nil {
			err = errors.Wrapf(err, "restoring assets in %s failed", baseDirectoryPath)
			return
		}
	} else if err != nil {
		err = errors.Wrapf(err, "stating %s failed", pr)
		return
	} else {
		logrus.Debugf("%s already exists, skipping restoring assets...", pr)
	}

	// Custom provision
	if fnP != nil {
		if err = fnP(baseDirectoryPath); err != nil {
			err = errors.Wrap(err, "custom provisioning failed")
			return
		}
	}
	return
}
