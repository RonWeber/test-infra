package deployer

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/test-infra/kubetest2/pkg/exec"
)

func (d *deployer) prepareGcpIfNeeded() error {
	//TODO(rweber): boskos
	if err := os.Setenv("CLOUDSDK_CORE_PRINT_UNHANDLED_TRACEBACKS", "1"); err != nil {
		return fmt.Errorf("could not set CLOUDSDK_CORE_PRINT_UNHANDLED_TRACEBACKS=1: %v", err)
	}
	endpoint, err := d.endpoint()
	if err != nil {
		return err
	}
	if err := os.Setenv("CLOUDSDK_API_ENDPOINT_OVERRIDES_CONTAINER", endpoint); err != nil {
		return err
	}

	if err := runWithOutput(exec.Command("gcloud", "config", "set", "project", d.project)); err != nil {
		return fmt.Errorf("Failed to set project %s : err %v", d.project, err)
	}

	// gcloud creds may have changed
	if err := activateServiceAccount(d.gcpServiceAccount); err != nil {
		return err
	}

	// Ensure ssh keys exist
	log.Print("Checking existing of GCP ssh keys...")
	k := filepath.Join(home(".ssh"), "google_compute_engine")
	if _, err := os.Stat(k); err != nil {
		return err
	}
	pk := k + ".pub"
	if _, err := os.Stat(pk); err != nil {
		return err
	}

	// Install custom gcloud version if necessary
	if d.gcpCloudSDK != "" {
		for i := 0; i < 3; i++ {
			if err := runWithOutput(exec.Command("gsutil", "-mq", "cp", "-r", d.gcpCloudSDK, home())); err == nil {
				break // Success!
			}
			time.Sleep(1 << uint(i) * time.Second)
		}
		for _, f := range []string{home(".gsutil"), home("repo"), home("cloudsdk")} {
			if _, err := os.Stat(f); err == nil || !os.IsNotExist(err) {
				if err = os.RemoveAll(f); err != nil {
					return err
				}
			}
		}

		install := home("repo", "google-cloud-sdk.tar.gz")
		if strings.HasSuffix(d.gcpCloudSDK, ".tar.gz") {
			install = home(filepath.Base(d.gcpCloudSDK))
		} else {
			if err := os.Rename(home(filepath.Base(d.gcpCloudSDK)), home("repo")); err != nil {
				return err
			}

			// Controls which gcloud components to install.
			pop, err := pushEnv("CLOUDSDK_COMPONENT_MANAGER_SNAPSHOT_URL", "file://"+home("repo", "components-2.json"))
			if err != nil {
				return err
			}
			defer pop()
		}

		if err := installGcloud(install, home("cloudsdk")); err != nil {
			return err
		}
		// gcloud creds may have changed
		if err := activateServiceAccount(d.gcpServiceAccount); err != nil {
			return err
		}
	}

	//TODO: kubemark
	return nil
}

// Activate service account if set or do nothing.
func activateServiceAccount(path string) error {
	if path == "" {
		return nil
	}
	return runWithOutput(exec.Command("gcloud", "auth", "activate-service-account", "--key-file="+path))
}

// home returns $HOME/part/part/part
func home(parts ...string) string {
	p := []string{os.Getenv("HOME")}
	for _, a := range parts {
		p = append(p, a)
	}
	return filepath.Join(p...)
}

// pushEnv pushes env=value and return a function that resets env
func pushEnv(env, value string) (func() error, error) {
	prev, present := os.LookupEnv(env)
	if err := os.Setenv(env, value); err != nil {
		return nil, fmt.Errorf("could not set %s: %v", env, err)
	}
	return func() error {
		if present {
			return os.Setenv(env, prev)
		}
		return os.Unsetenv(env)
	}, nil
}

// insertPath does export PATH=path:$PATH
func insertPath(path string) error {
	return os.Setenv("PATH", fmt.Sprintf("%v:%v", path, os.Getenv("PATH")))
}

// Install cloudsdk tarball to location, updating PATH
func installGcloud(tarball string, location string) error {

	if err := os.MkdirAll(location, 0775); err != nil {
		return err
	}

	if err := runWithOutput(exec.Command("tar", "xzf", tarball, "-C", location)); err != nil {
		return err
	}

	if err := runWithOutput(exec.Command(filepath.Join(location, "google-cloud-sdk", "install.sh"), "--disable-installation-options", "--bash-completion=false", "--path-update=false", "--usage-reporting=false")); err != nil {
		return err
	}

	if err := insertPath(filepath.Join(location, "google-cloud-sdk", "bin")); err != nil {
		return err
	}

	if err := runWithOutput(exec.Command("gcloud", "components", "install", "alpha")); err != nil {
		return err
	}

	if err := runWithOutput(exec.Command("gcloud", "components", "install", "beta")); err != nil {
		return err
	}

	if err := runWithOutput(exec.Command("gcloud", "info")); err != nil {
		return err
	}
	return nil
}
