/*
Copyright 2026 Myelin Contributors.

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
	"crypto/tls"
	"flag"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	myelinv1alpha1 "github.com/myelinio/myelin/api/v1alpha1"
	"github.com/myelinio/myelin/internal/controller"
	"github.com/myelinio/myelin/internal/crypto"
	"github.com/myelinio/myelin/internal/keystore"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(myelinv1alpha1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var enableHTTP2 bool
	var keySecretName string
	var keySecretNamespace string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address the metrics endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false, "Enable HTTP/2 for metrics and webhook servers.")
	flag.StringVar(&keySecretName, "key-secret-name", "myelin-operator-key", "Name of the Secret holding the operator RSA key pair.")
	flag.StringVar(&keySecretNamespace, "key-secret-namespace", "myelin-system", "Namespace of the operator RSA key Secret.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	tlsOpts := []func(*tls.Config){}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			c.NextProtos = []string{"http/1.1"}
		})
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
			TLSOpts:     tlsOpts,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "myelin.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Load or generate the operator RSA key pair.
	// The key is persisted in a Kubernetes Secret so it survives pod restarts.
	ks := keystore.New(mgr.GetClient(), keySecretName, keySecretNamespace)
	privateKey, err := ks.LoadOrGenerate(ctrl.SetupSignalHandler(), crypto.GenerateKeyPair)
	if err != nil {
		setupLog.Error(err, "unable to load or generate operator key pair")
		os.Exit(1)
	}
	setupLog.Info("operator key pair ready")

	if err = (&controller.MyelinSecretReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		PrivateKey: privateKey,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "MyelinSecret")
		os.Exit(1)
	}

	if err = (&controller.MyelinSecretPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "MyelinSecretPolicy")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting myelin operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
