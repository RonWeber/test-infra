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

package main

import (
	"fmt"
	"k8s.io/test-infra/testgrid/config"
	"path"
	"strings"

	prowapi "k8s.io/test-infra/prow/apis/prowjobs/v1"
	prowConfig "k8s.io/test-infra/prow/config"
	"k8s.io/test-infra/prow/pod-utils/downwardapi"
	prowGCS "k8s.io/test-infra/prow/pod-utils/gcs"
)

const testgridCreateTestGroupAnnotation = "testgrid-create-test-group"
const testgridDashboardsAnnotation = "testgrid-dashboards"
const testgridTabNameAnnotation = "testgrid-tab-name"
const descriptionAnnotation = "description"

// Talk to @michelle192837 if you're thinking about adding more of these!

func applySingleProwjobAnnotations(c *Config, pc *prowConfig.Config, j prowConfig.JobBase, jobType prowapi.ProwJobType) error {
	tabName := j.Name
	testGroupName := j.Name
	description := j.Name

	mustMakeGroup := j.Annotations[testgridCreateTestGroupAnnotation] == "true"
	dashboards, addToDashboards := j.Annotations[testgridDashboardsAnnotation]
	mightMakeGroup := mustMakeGroup || addToDashboards

	if mightMakeGroup {
		if c.config.FindTestGroup(testGroupName) != nil {
			if mustMakeGroup {
				return fmt.Errorf("test group %q already exists", testGroupName)
			}
		} else {
			var prefix string
			if j.DecorationConfig != nil && j.DecorationConfig.GCSConfiguration != nil {
				prefix = path.Join(j.DecorationConfig.GCSConfiguration.Bucket, j.DecorationConfig.GCSConfiguration.PathPrefix)
			} else if pc.Plank.DefaultDecorationConfig != nil && pc.Plank.DefaultDecorationConfig.GCSConfiguration != nil {
				prefix = path.Join(pc.Plank.DefaultDecorationConfig.GCSConfiguration.Bucket, pc.Plank.DefaultDecorationConfig.GCSConfiguration.PathPrefix)
			} else {
				return fmt.Errorf("job %s: couldn't figure out a default decoration config", j.Name)
			}

			g := &config.TestGroup{
				Name:      testGroupName,
				GcsPrefix: path.Join(prefix, prowGCS.RootForSpec(&downwardapi.JobSpec{Job: j.Name, Type: jobType})),
			}
			ReconcileTestGroup(g, c.defaultConfig.DefaultTestGroup)
			c.config.TestGroups = append(c.config.TestGroups, g)
		}
	}

	if tn, ok := j.Annotations[testgridTabNameAnnotation]; ok {
		tabName = tn
	}
	if d := j.Annotations[descriptionAnnotation]; d != "" {
		description = d
	}

	if addToDashboards {
		for _, dashboardName := range strings.Split(dashboards, ",") {
			dashboardName = strings.TrimSpace(dashboardName)
			d := c.config.FindDashboard(dashboardName)
			if d == nil {
				return fmt.Errorf("couldn't find dashboard %q for job %q", dashboardName, j.Name)
			}
			dt := &config.DashboardTab{
				Name:          tabName,
				TestGroupName: testGroupName,
				Description:   description,
			}
			ReconcileDashboardTab(dt, c.defaultConfig.DefaultDashboardTab)
			d.DashboardTab = append(d.DashboardTab, dt)
		}
	}

	return nil
}

func applyProwjobAnnotations(c *Config, prowConfigAgent *prowConfig.Agent) error {
	pc := prowConfigAgent.Config()
	if pc == nil {
		return nil
	}
	jobs := prowConfigAgent.Config().JobConfig
	for _, j := range jobs.AllPeriodics() {
		if err := applySingleProwjobAnnotations(c, pc, j.JobBase, prowapi.PeriodicJob); err != nil {
			return err
		}
	}
	for _, j := range jobs.AllPostsubmits(nil) {
		if err := applySingleProwjobAnnotations(c, pc, j.JobBase, prowapi.PostsubmitJob); err != nil {
			return err
		}
	}
	for _, j := range jobs.AllPresubmits(nil) {
		if err := applySingleProwjobAnnotations(c, pc, j.JobBase, prowapi.PresubmitJob); err != nil {
			return err
		}
	}
	return nil
}
