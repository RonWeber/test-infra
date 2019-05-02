/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package deployer implements the kubetest2 GKE deployer
package deployer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/pflag"

	"k8s.io/test-infra/kubetest2/pkg/exec"
	// "k8s.io/test-infra/kubetest2/pkg/metadata"
	"k8s.io/test-infra/kubetest2/pkg/process"
	"k8s.io/test-infra/kubetest2/pkg/types"
)

// Name is the name of the deployer
const Name = "gke"

const (
	defaultPool   = "default"
	e2eAllow      = "tcp:22,tcp:80,tcp:8080,tcp:30000-32767,udp:30000-32767"
	defaultCreate = "container clusters create --quiet"
)

var (
	// poolRe matches instance group URLs of the form `https://www.googleapis.com/compute/v1/projects/some-project/zones/a-zone/instanceGroupManagers/gke-some-cluster-some-pool-90fcb815-grp`. Match meaning:
	// m[0]: path starting with zones/
	// m[1]: zone
	// m[2]: pool name (passed to e2es)
	// m[3]: unique hash (used as nonce for firewall rules)
	poolRe = regexp.MustCompile(`zones/([^/]+)/instanceGroupManagers/(gke-.*-([0-9a-f]{8})-grp)$`)

	urlRe = regexp.MustCompile(`https://.*/`)
)

type gkeNodePool struct {
	Nodes       int
	MachineType string
	ExtraArgs   []string
}

type ig struct {
	path string
	zone string
	name string
	uniq string
}

type deployer struct {
	// generic parts
	commonOptions types.Options
	// gke specific details
	project                     string
	zone                        string
	region                      string
	additionalZones             string
	nodeLocations               string
	cluster                     string
	shapeFlag                   string
	network                     string
	subnetwork                  string
	subnetworkRegion            string
	image                       string
	imageFamily                 string
	imageProject                string
	commandGroupFlag            string
	createCommandFlag           string
	singleZoneNodeInstanceGroup bool
	customSubnetFlag            string

	setup          bool   //!
	kubecfg        string //!
	instanceGroups []*ig  //!

	gkeSingleZoneNodeInstanceGroup bool

	gkeEnvironment string

	localLogsDir string
	gcsLogsDir   string
}

// New implements deployer.New for gke
func New(opts types.Options) (types.Deployer, *pflag.FlagSet) {
	// create a deployer object and set fields that are not flag controlled
	d := &deployer{
		commonOptions: opts,
		localLogsDir:  filepath.Join(opts.ArtifactsDir(), "logs"),
	}

	// register flags and return
	return d, bindFlags(d)
}

func (d *deployer) verifyFlags() error {
	if d.cluster == "" {
		return fmt.Errorf("--cluster must be set for GKE deployment")
	}
	if d.project == "" {
		return fmt.Errorf("--project must be set for GKE deployment")
	}
	if d.network == "" {
		return fmt.Errorf("--network must be set for GKE deployment")
	}
	if d.image == "" {
		return fmt.Errorf("--node-image must be set for GKE deployment")
	}
	if strings.ToUpper(d.image) == "CUSTOM" {
		if d.imageFamily == "" || d.imageProject == "" {
			return fmt.Errorf("--image-family and --image-project must be set for GKE deployment if --node-image=CUSTOM")
		}
	}
	return nil
}

func (d *deployer) location() (string, error) {
	if d.zone == "" && d.region == "" {
		return "", fmt.Errorf("--zone or --region must be set for GKE deployment")
	} else if d.zone != "" && d.region != "" {
		return "", fmt.Errorf("--zone and --region cannot both be set")
	}

	if d.zone != "" {
		return "--zone=" + d.zone, nil
	} else {
		return "--region" + d.region, nil
	}
}

func (d *deployer) shape() (map[string]gkeNodePool, error) {
	var result map[string]gkeNodePool
	err := json.Unmarshal([]byte(d.shapeFlag), &result)
	if err != nil {
		return nil, fmt.Errorf("--shape must be valid JSON, unmarshal error: %v, JSON: %q", err, d.shapeFlag)
	}
	if _, ok := result[defaultPool]; !ok {
		return nil, fmt.Errorf("--shape must include a node pool named 'default', found %q", d.shapeFlag)
	}
	return result, nil
}

func (d *deployer) createCommand() []string {
	return append(strings.Fields(d.commandGroupFlag), strings.Fields(d.createCommandFlag)...)
}

func (d *deployer) endpoint() (string, error) {
	var result string
	switch env := d.gkeEnvironment; {
	case env == "test":
		result = "https://test-container.sandbox.googleapis.com/"
	case env == "staging":
		result = "https://staging-container.sandbox.googleapis.com/"
	case env == "prod":
		result = "https://container.googleapis.com/"
	case urlRe.MatchString(env):
		result = env
	default:
		return "", fmt.Errorf("--gke-environment must be one of {test,staging,prod} or match %v, found %q", urlRe, env)
	}
	return "", nil
}

// assert that New implements types.NewDeployer
var _ types.NewDeployer = New

func bindFlags(d *deployer) *pflag.FlagSet {
	flags := pflag.NewFlagSet(Name, pflag.ContinueOnError)

	flags.StringVar(&d.additionalZones, "additional-zones", "", "(List of additional Google Compute Engine zones to use. Clusters are created symmetrically across zones by default, see --shape for details.")
	flags.StringVar(&d.cluster, "cluster", "", "Cluster name. Must be set for --deployment=gke (TODO: other deployments).")
	flags.StringVar(&d.commandGroupFlag, "command-group", "", "Use a different gcloud track (e.g. 'alpha') for all 'gcloud container' commands. Note: This is added to --create-command on create. You should only use --command-group if you need to change the gcloud track for *every* gcloud container command.")
	flags.StringVar(&d.createCommandFlag, "create-command", defaultCreate, "gcloud subcommand used to create a cluster. Modify if you need to pass arbitrary arguments to create.")
	flags.StringVar(&d.customSubnetFlag, "custom-subnet", "", "If specified, we create a custom subnet with the specified options and use it for the gke cluster. The format should be '<subnet-name> --region=<subnet-gcp-region> --range=<subnet-cidr> <any other optional params>'.")
	flags.StringVar(&d.gcpCloudSdk, "gcp-cloud-sdk", "", "Install/upgrade google-cloud-sdk to the gs:// path if set")
	flags.StringVar(&d.gcpProjectType, "gcp-project-type", "", "Explicitly indicate which project type to select from boskos")
	flags.StringVar(&d.gcpServiceAccount, "gcp-service-account", "", "Service account to activate before using gcloud")
	flags.StringVar(&d.gkeEnvironment, "gke-environment", "", "Container API endpoint to use, one of 'test', 'staging', 'prod',who or a custom https:// URL")
	flags.StringVar(&d.imageFamily, "image-family", "", "Node image family from which to use the latest image, required when --node-image=CUSTOM")
	flags.StringVar(&d.imageProject, "image-project", "", "Project containing node image family, required when --node-image=CUSTOM")
	flags.StringVar(&d.network, "network", "", "Cluster network. Must be set.")
	flags.StringVar(&d.image, "node-image", "", "Node image type (cos|container_vm)")
	flags.StringVar(&d.nodeLocations, "node-locations", "", "List of Google Compute Engine zones to use.")
	flags.StringVar(&d.project, "project", "", "For use with gcloud commands")
	flags.StringVar(&d.region, "region", "", "For use with gcloud commands")
	flags.BoolVar(&d.singleZoneNodeInstanceGroup, "single-zone-node-instance-group", true, "(gke only) Add instance groups from a single zone to the NODE_INSTANCE_GROUP env variable.")
	flags.StringVar(&d.zone, "zone", "", "For use with gcloud commands")
	flags.StringVar(&d.shapeString, "shape", `{"default":{"Nodes":3,"MachineType":"n1-standard-2"}}`, `A JSON description of node pools to create. The node pool 'default' is required and used for initial cluster creation. All node pools are symmetric across zones, so the cluster total node count is {total nodes in --gke-shape} * {1 + (length of --gke-additional-zones)}. Example: '{"default":{"Nodes":999,"MachineType:":"n1-standard-1"},"heapster":{"Nodes":1, "MachineType":"n1-standard-8", "ExtraArgs": []}}`)

	return flags
}

// assert that deployer implements types.Deployer
var _ types.Deployer = &deployer{}

// Deployer implementation methods below

func (d *deployer) Up() error {
	if err := d.verifyFlags(); err != nil {
		return err
	}
	// Create network if it doesn't exist.
	if control.NoOutput(exec.Command("gcloud", "compute", "networks", "describe", d.network,
		"--project="+d.project,
		"--format=value(name)")) != nil {
		// Assume error implies non-existent.
		log.Printf("Couldn't describe network '%s', assuming it doesn't exist and creating it", d.network)
		if err := control.FinishRunning(exec.Command("gcloud", "compute", "networks", "create", d.network,
			"--project="+d.project,
			"--subnet-mode=auto")); err != nil {
			return err
		}
	}
	// Create a custom subnet in that network if it was asked for.
	if *gkeCustomSubnet != "" {
		customSubnetFields := strings.Fields(*gkeCustomSubnet)
		createSubnetCommand := []string{"compute", "networks", "subnets", "create"}
		createSubnetCommand = append(createSubnetCommand, "--project="+d.project, "--network="+d.network)
		createSubnetCommand = append(createSubnetCommand, customSubnetFields...)
		if err := control.FinishRunning(exec.Command("gcloud", createSubnetCommand...)); err != nil {
			return err
		}
		d.subnetwork = customSubnetFields[0]
		d.subnetworkRegion = customSubnetFields[1]
	}

	def := d.shape[defaultPool]
	args := make([]string, len(d.createCommand))
	copy(args, d.createCommand)
	args = append(args,
		"--project="+d.project,
		d.location,
		"--machine-type="+def.MachineType,
		"--image-type="+d.image,
		"--num-nodes="+strconv.Itoa(def.Nodes),
		"--network="+d.network,
	)

	args = append(args, def.ExtraArgs...)
	if strings.ToUpper(d.image) == "CUSTOM" {
		args = append(args, "--image-family="+d.imageFamily)
		args = append(args, "--image-project="+d.imageProject)
	}
	if d.subnetwork != "" {
		args = append(args, "--subnetwork="+d.subnetwork)
	}
	if d.additionalZones != "" {
		args = append(args, "--additional-zones="+d.additionalZones)
		if err := os.Setenv("MULTIZONE", "true"); err != nil {
			return fmt.Errorf("error setting MULTIZONE env variable: %v", err)
		}

	}
	if d.nodeLocations != "" {
		args = append(args, "--node-locations="+d.nodeLocations)
		numNodeLocations := strings.Split(d.nodeLocations, ",")
		if len(numNodeLocations) > 1 {
			if err := os.Setenv("MULTIZONE", "true"); err != nil {
				return fmt.Errorf("error setting MULTIZONE env variable: %v", err)
			}
		}
	}
	// TODO(zmerlynn): The version should be plumbed through Extract
	// or a separate flag rather than magic env variables.
	if v := os.Getenv("CLUSTER_API_VERSION"); v != "" {
		args = append(args, "--cluster-version="+v)
	}
	args = append(args, d.cluster)
	if err := control.FinishRunning(exec.Command("gcloud", args...)); err != nil {
		return fmt.Errorf("error creating cluster: %v", err)
	}
	for poolName, pool := range d.shape {
		if poolName == defaultPool {
			continue
		}
		poolArgs := []string{"node-pools", "create", poolName,
			"--cluster=" + d.cluster,
			"--project=" + d.project,
			d.location,
			"--machine-type=" + pool.MachineType,
			"--num-nodes=" + strconv.Itoa(pool.Nodes)}
		poolArgs = append(poolArgs, pool.ExtraArgs...)
		if err := control.FinishRunning(exec.Command("gcloud", d.containerArgs(poolArgs...)...)); err != nil {
			return fmt.Errorf("error creating node pool %q: %v", poolName, err)
		}
	}
	return nil
}

func (d *deployer) IsUp() (bool, error) {
	return isUp(g)
}

func (d *deployer) Down() error {
	args := []string{
		"delete", "cluster",
		"--name", d.clusterName,
	}
	if d.logLevel != "" {
		args = append(args, "--loglevel", d.logLevel)
	}

	println("Down(): deleting kind cluster...\n")
	// we want to see the output so use process.ExecJUnit
	return process.ExecJUnit("kind", args, os.Environ())
}

// DumpClusterLogs for GKE generates a small script that wraps
// log-dump.sh with the appropriate shell-fu to get the cluster
// dumped.
//
// TODO(zmerlynn): This whole path is really gross, but this seemed
// the least gross hack to get this done.
//
// TODO(shyamjvs): Make this work with multizonal and regional clusters.
func (d *deployer) DumpClusterLogs() error {
	// gkeLogDumpTemplate is a template of a shell script where
	// - %[1]s is the project
	// - %[2]s is the zone
	// - %[3]s is a filter composed of the instance groups
	// - %[4]s is the log-dump.sh command line
	const gkeLogDumpTemplate = `
function log_dump_custom_get_instances() {
  if [[ $1 == "master" ]]; then
    return 0
  fi

  gcloud compute instances list '--project=%[1]s' '--filter=%[4]s' '--format=get(name)'
}
export -f log_dump_custom_get_instances
# Set below vars that log-dump.sh expects in order to use scp with gcloud.
export PROJECT=%[1]s
export ZONE='%[2]s'
export KUBERNETES_PROVIDER=gke
export KUBE_NODE_OS_DISTRIBUTION='%[3]s'
%[5]s
`
	// Prevent an obvious injection.
	if strings.Contains(d.localLogsDir, "'") || strings.Contains(d.gcsLogsDir, "'") {
		return fmt.Errorf("%q or %q contain single quotes - nice try", d.localLogsDir, d.gcsLogsDir)
	}

	// Generate a slice of filters to be OR'd together below
	if err := d.getInstanceGroups(); err != nil {
		return err
	}
	var filters []string
	for _, ig := range d.instanceGroups {
		filters = append(filters, fmt.Sprintf("(metadata.created-by:*%s)", ig.path))
	}

	// Generate the log-dump.sh command-line
	var dumpCmd string
	if d.gcsLogsDir == "" {
		dumpCmd = fmt.Sprintf("./cluster/log-dump/log-dump.sh '%s'", d.localLogsDir)
	} else {
		dumpCmd = fmt.Sprintf("./cluster/log-dump/log-dump.sh '%s' '%s'", d.localLogsDir, d.gcsLogsDir)
	}
	return control.FinishRunning(exec.Command("bash", "-c", fmt.Sprintf(gkeLogDumpTemplate,
		d.project,
		d.zone,
		os.Getenv("NODE_OS_DISTRIBUTION"),
		strings.Join(filters, " OR "),
		dumpCmd)))
}

func (d *deployer) TestSetup() error {
	if d.setup {
		// Ensure setup is a singleton.
		return nil
	}
	if err := d.getKubeConfig(); err != nil {
		return err
	}
	if err := d.getInstanceGroups(); err != nil {
		return err
	}
	if err := d.ensureFirewall(); err != nil {
		return err
	}
	if err := d.setupEnv(); err != nil {
		return err
	}
	d.setup = true
	return nil
}

func (d *deployer) getKubeConfig() error {
	info, err := os.Stat(d.kubecfg)
	if err != nil {
		return err
	}
	if info.Size() > 0 {
		// Assume that if we already have it, it's good.
		return nil
	}
	if err := os.Setenv("KUBECONFIG", d.kubecfg); err != nil {
		return err
	}
	if err := control.FinishRunning(exec.Command("gcloud", d.containerArgs("clusters", "get-credentials", d.cluster,
		"--project="+d.project,
		d.location)...)); err != nil {
		return fmt.Errorf("error executing get-credentials: %v", err)
	}
	return nil
}

func (d *deployer) Build() error {
	if err := d.verifyFlags(); err != nil {
		return err
	}
	// TODO(bentheelder): build type should be configurable
	args := []string{
		"build", "node-image",
	}
	if d.logLevel != "" {
		args = append(args, "--loglevel", d.logLevel)
	}
	if d.buildType != "" {
		args = append(args, "--type", d.buildType)
	}
	// set the explicitly specified image name if set
	if d.nodeImage != "" {
		args = append(args, "--image", d.nodeImage)
	} else if d.commonOptions.ShouldBuild() {
		// otherwise if we just built an image, use that
		args = append(args, "--image", kindDefaultBuiltImageName)
	}

	println("Build(): building kind node image...\n")
	// we want to see the output so use process.ExecJUnit
	return process.ExecJUnit("kind", args, os.Environ())
}

// setupEnv is to appease ginkgo-e2e.sh and other pieces of the e2e infrastructure. It
// would be nice to handle this elsewhere, and not with env
// variables. c.f. kubernetes/test-infra#3330.
func (d *deployer) setupEnv() error {
	// If singleZoneNodeInstanceGroup is true, set NODE_INSTANCE_GROUP to the
	// names of instance groups that are in the same zone as the lexically first
	// instance group. Otherwise set NODE_INSTANCE_GROUP to the names of all
	// instance groups.
	var filt []string
	zone := d.instanceGroups[0].zone
	for _, ig := range d.instanceGroups {
		if !d.singleZoneNodeInstanceGroup || ig.zone == zone {
			filt = append(filt, ig.name)
		}
	}
	if err := os.Setenv("NODE_INSTANCE_GROUP", strings.Join(filt, ",")); err != nil {
		return fmt.Errorf("error setting NODE_INSTANCE_GROUP: %v", err)
	}
	return nil
}

func (d *deployer) ensureFirewall() error {
	if d.network == "default" {
		return nil
	}
	firewall, err := d.getClusterFirewall()
	if err != nil {
		return fmt.Errorf("error getting unique firewall: %v", err)
	}
	if control.NoOutput(exec.Command("gcloud", "compute", "firewall-rules", "describe", firewall,
		"--project="+d.project,
		"--format=value(name)")) == nil {
		// Assume that if this unique firewall exists, it's good to go.
		return nil
	}
	log.Printf("Couldn't describe firewall '%s', assuming it doesn't exist and creating it", firewall)

	tagOut, err := exec.Command("gcloud", "compute", "instances", "list",
		"--project="+d.project,
		"--filter=metadata.created-by:*"+d.instanceGroups[0].path,
		"--limit=1",
		"--format=get(tags.items)").Output()
	if err != nil {
		return fmt.Errorf("instances list failed: %s", util.ExecError(err))
	}
	tag := strings.TrimSpace(string(tagOut))
	if tag == "" {
		return fmt.Errorf("instances list returned no instances (or instance has no tags)")
	}

	if err := control.FinishRunning(exec.Command("gcloud", "compute", "firewall-rules", "create", firewall,
		"--project="+d.project,
		"--network="+d.network,
		"--allow="+e2eAllow,
		"--target-tags="+tag)); err != nil {
		return fmt.Errorf("error creating e2e firewall: %v", err)
	}
	return nil
}

func (d *deployer) getInstanceGroups() error {
	if len(d.instanceGroups) > 0 {
		return nil
	}
	igs, err := exec.Command("gcloud", d.containerArgs("clusters", "describe", d.cluster,
		"--format=value(instanceGroupUrls)",
		"--project="+d.project,
		d.location)...).Output()
	if err != nil {
		return fmt.Errorf("instance group URL fetch failed: %s", util.ExecError(err))
	}
	igURLs := strings.Split(strings.TrimSpace(string(igs)), ";")
	if len(igURLs) == 0 {
		return fmt.Errorf("no instance group URLs returned by gcloud, output %q", string(igs))
	}
	sort.Strings(igURLs)
	for _, igURL := range igURLs {
		m := poolRe.FindStringSubmatch(igURL)
		if len(m) == 0 {
			return fmt.Errorf("instanceGroupUrl %q did not match regex %v", igURL, poolRe)
		}
		d.instanceGroups = append(d.instanceGroups, &ig{path: m[0], zone: m[1], name: m[2], uniq: m[3]})
	}
	return nil
}

func (d *deployer) getClusterFirewall() (string, error) {
	if err := d.getInstanceGroups(); err != nil {
		return "", err
	}
	// We want to ensure that there's an e2e-ports-* firewall rule
	// that maps to the cluster nodes, but the target tag for the
	// nodes can be slow to get. Use the hash from the lexically first
	// node pool instead.
	return "e2e-ports-" + d.instanceGroups[0].uniq, nil
}

// This function ensures that all firewall-rules are deleted from specific network.
// We also want to keep in logs that there were some resources leaking.
func (d *deployer) cleanupNetworkFirewalls() (int, error) {
	fws, err := exec.Command("gcloud", "compute", "firewall-rules", "list",
		"--format=value(name)",
		"--project="+d.project,
		"--filter=network:"+d.network).Output()
	if err != nil {
		return 0, fmt.Errorf("firewall rules list failed: %s", util.ExecError(err))
	}
	if len(fws) > 0 {
		fwList := strings.Split(strings.TrimSpace(string(fws)), "\n")
		log.Printf("Network %s has %v undeleted firewall rules %v", d.network, len(fwList), fwList)
		commandArgs := []string{"compute", "firewall-rules", "delete", "-q"}
		commandArgs = append(commandArgs, fwList...)
		commandArgs = append(commandArgs, "--project="+d.project)
		errFirewall := control.FinishRunning(exec.Command("gcloud", commandArgs...))
		if errFirewall != nil {
			return 0, fmt.Errorf("error deleting firewall: %v", errFirewall)
		}
		return len(fwList), nil
	}
	return 0, nil
}

func (d *deployer) Down() error {
	firewall, err := d.getClusterFirewall()
	if err != nil {
		// This is expected if the cluster doesn't exist.
		return nil
	}
	d.instanceGroups = nil

	// We best-effort try all of these and report errors as appropriate.
	errCluster := control.FinishRunning(exec.Command(
		"gcloud", d.containerArgs("clusters", "delete", "-q", d.cluster,
			"--project="+d.project,
			d.location)...))

	// don't delete default network
	if d.network == "default" {
		if errCluster != nil {
			log.Printf("Error deleting cluster using default network, allow the error for now %s", errCluster)
		}
		return nil
	}

	var errFirewall error
	if control.NoOutput(exec.Command("gcloud", "compute", "firewall-rules", "describe", firewall,
		"--project="+d.project,
		"--format=value(name)")) == nil {
		log.Printf("Found rules for firewall '%s', deleting them", firewall)
		errFirewall = control.FinishRunning(exec.Command("gcloud", "compute", "firewall-rules", "delete", "-q", firewall,
			"--project="+d.project))
	} else {
		log.Printf("Found no rules for firewall '%s', assuming resources are clean", firewall)
	}
	numLeakedFWRules, errCleanFirewalls := d.cleanupNetworkFirewalls()
	var errSubnet error
	if d.subnetwork != "" {
		errSubnet = control.FinishRunning(exec.Command("gcloud", "compute", "networks", "subnets", "delete", "-q", d.subnetwork,
			d.subnetworkRegion, "--project="+d.project))
	}
	errNetwork := control.FinishRunning(exec.Command("gcloud", "compute", "networks", "delete", "-q", d.network,
		"--project="+d.project))
	if errCluster != nil {
		return fmt.Errorf("error deleting cluster: %v", errCluster)
	}
	if errFirewall != nil {
		return fmt.Errorf("error deleting firewall: %v", errFirewall)
	}
	if errCleanFirewalls != nil {
		return fmt.Errorf("error cleaning-up firewalls: %v", errCleanFirewalls)
	}
	if errSubnet != nil {
		return fmt.Errorf("error deleting subnetwork: %v", errSubnet)
	}
	if errNetwork != nil {
		return fmt.Errorf("error deleting network: %v", errNetwork)
	}
	if numLeakedFWRules > 0 {
		return fmt.Errorf("leaked firewall rules")
	}
	return nil
}

func (d *deployer) containerArgs(args ...string) []string {
	return append(append(append([]string{}, d.commandGroup...), "container"), args...)
}

func (d *deployer) GetClusterCreated(gcpProject string) (time.Time, error) {
	res, err := control.Output(exec.Command(
		"gcloud",
		"compute",
		"instance-groups",
		"list",
		"--project="+gcpProject,
		"--format=json(name,creationTimestamp)"))
	if err != nil {
		return time.Time{}, fmt.Errorf("list instance-group failed : %v", err)
	}

	created, err := getLatestClusterUpTime(string(res))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse time failed : got gcloud res %s, err %v", string(res), err)
	}
	return created, nil
}
