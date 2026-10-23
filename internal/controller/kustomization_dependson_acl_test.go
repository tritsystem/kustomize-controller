/*
Copyright 2026 The Flux authors

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

package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	apiacl "github.com/fluxcd/pkg/apis/acl"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/fluxcd/pkg/testserver"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	. "github.com/onsi/gomega"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
)

// TestKustomizationReconciler_NoCrossNamespaceRefs_DependsOn proves that
// spec.dependsOn (unlike spec.sourceRef, see TestKustomizationReconciler_NoCrossNamespaceRefs
// in kustomization_acl_test.go) is not gated by NoCrossNamespaceRefs. A tenant
// restricted to their own namespace can still name a Kustomization in any
// other namespace as a dependency, and if they set readyExpr, the controller
// evaluates their own CEL expression against that dependency's FULL spec+status
// -- a boolean oracle over an object outside their tenant boundary.
func TestKustomizationReconciler_NoCrossNamespaceRefs_DependsOn(t *testing.T) {
	g := NewWithT(t)
	id := "tenant-" + randStringRunes(5)
	depNamespace := "victim-" + randStringRunes(5)

	g.Expect(createNamespace(id)).To(Succeed())
	g.Expect(createNamespace(depNamespace)).To(Succeed())

	// The "victim" Kustomization, in a namespace the attacking tenant has no
	// RBAC visibility into. .spec.path here stands in for any non-Secret but
	// sensitive per-tenant metadata (it could just as easily be sourceRef
	// name/namespace, inline patches, or labels).
	secretPath := "internal/ops/prod-db-migration"
	dep := &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "victim-" + randStringRunes(5),
			Namespace: depNamespace,
		},
		Spec: kustomizev1.KustomizationSpec{
			Interval: metav1.Duration{Duration: reconciliationInterval},
			Path:     secretPath,
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind: sourcev1.GitRepositoryKind,
				Name: "does-not-need-to-exist",
			},
		},
	}
	g.Expect(k8sClient.Create(context.Background(), dep)).To(Succeed())

	// Give dep a persisted Ready status directly -- checkDependencies only
	// needs a real, fetchable object; it does not need dep to have gone
	// through its own successful reconcile.
	dep.Status.Conditions = []metav1.Condition{{
		Type:               meta.ReadyCondition,
		Status:             metav1.ConditionTrue,
		Reason:             meta.ReconciliationSucceededReason,
		LastTransitionTime: metav1.Now(),
	}}
	dep.Status.ObservedGeneration = dep.Generation
	g.Expect(k8sClient.Status().Update(context.Background(), dep)).To(Succeed())

	// The attacking tenant's own Kustomization: same-namespace source (so the
	// existing sourceRef gate is not what's under test), depending cross-
	// namespace on the victim with a readyExpr that only evaluates true if it
	// can read dep.spec.path -- a field the tenant was never granted access to.
	artifact, err := testServer.ArtifactFromFiles([]testserver.File{{
		Name: "secret.yaml",
		Body: fmt.Sprintf("---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\nstringData:\n  key: %q\n", id, randStringRunes(5)),
	}})
	g.Expect(err).NotTo(HaveOccurred())

	repositoryName := types.NamespacedName{Name: randStringRunes(5), Namespace: id}
	g.Expect(applyGitRepository(repositoryName, artifact, "v1.0.0")).To(Succeed())

	self := &kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "self-" + randStringRunes(5),
			Namespace: id,
		},
		Spec: kustomizev1.KustomizationSpec{
			Interval:        metav1.Duration{Duration: reconciliationInterval},
			Path:            "./",
			TargetNamespace: id,
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind: sourcev1.GitRepositoryKind,
				Name: repositoryName.Name,
			},
			DependsOn: []kustomizev1.DependencyReference{
				{
					Name:      dep.Name,
					Namespace: dep.Namespace,
					ReadyExpr: fmt.Sprintf(`dep.spec.path.matches("^%s.*")`, secretPath),
				},
			},
		},
	}

	reconciler.NoCrossNamespaceRefs = true
	defer func() { reconciler.NoCrossNamespaceRefs = false }()

	g.Expect(k8sClient.Create(context.Background(), self)).To(Succeed())

	resultK := &kustomizev1.Kustomization{}
	var readyCondition *metav1.Condition
	g.Eventually(func() bool {
		_ = k8sClient.Get(context.Background(), client.ObjectKeyFromObject(self), resultK)
		readyCondition = apimeta.FindStatusCondition(resultK.Status.Conditions, meta.ReadyCondition)
		return readyCondition != nil
	}, timeout, time.Second).Should(BeTrue())

	// Desired (fixed) behavior: cross-namespace dependsOn is rejected the same
	// way cross-namespace sourceRef already is, access denied, stalled, never
	// evaluating the tenant's CEL expression against the out-of-namespace
	// object. Pre-fix, this assertion fails because the readyExpr oracle
	// actually ran and matched (self never gets AccessDenied; the generic
	// "Dependencies do not meet ready condition" transient-retry path or a
	// successful reconcile happens instead).
	g.Expect(readyCondition.Reason).To(Equal(apiacl.AccessDeniedReason))
	g.Expect(apimeta.IsStatusConditionTrue(resultK.Status.Conditions, meta.StalledCondition)).Should(BeTrue())
}
