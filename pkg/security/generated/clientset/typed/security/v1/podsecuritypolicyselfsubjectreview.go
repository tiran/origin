package v1

import (
	v1 "github.com/openshift/origin/pkg/security/apis/security/v1"
	rest "k8s.io/client-go/rest"
)

// PodSecurityPolicySelfSubjectReviewsGetter has a method to return a PodSecurityPolicySelfSubjectReviewInterface.
// A group's client should implement this interface.
type PodSecurityPolicySelfSubjectReviewsGetter interface {
	PodSecurityPolicySelfSubjectReviews(namespace string) PodSecurityPolicySelfSubjectReviewInterface
}

// PodSecurityPolicySelfSubjectReviewInterface has methods to work with PodSecurityPolicySelfSubjectReview resources.
type PodSecurityPolicySelfSubjectReviewInterface interface {
	Create(*v1.PodSecurityPolicySelfSubjectReview) (*v1.PodSecurityPolicySelfSubjectReview, error)
	PodSecurityPolicySelfSubjectReviewExpansion
}

// podSecurityPolicySelfSubjectReviews implements PodSecurityPolicySelfSubjectReviewInterface
type podSecurityPolicySelfSubjectReviews struct {
	client rest.Interface
	ns     string
}

// newPodSecurityPolicySelfSubjectReviews returns a PodSecurityPolicySelfSubjectReviews
func newPodSecurityPolicySelfSubjectReviews(c *SecurityV1Client, namespace string) *podSecurityPolicySelfSubjectReviews {
	return &podSecurityPolicySelfSubjectReviews{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Create takes the representation of a podSecurityPolicySelfSubjectReview and creates it.  Returns the server's representation of the podSecurityPolicySelfSubjectReview, and an error, if there is any.
func (c *podSecurityPolicySelfSubjectReviews) Create(podSecurityPolicySelfSubjectReview *v1.PodSecurityPolicySelfSubjectReview) (result *v1.PodSecurityPolicySelfSubjectReview, err error) {
	result = &v1.PodSecurityPolicySelfSubjectReview{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("podsecuritypolicyselfsubjectreviews").
		Body(podSecurityPolicySelfSubjectReview).
		Do().
		Into(result)
	return
}
