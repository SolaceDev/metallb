/*


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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required. Any new fields you add must have json tags for the fields to be serialized.

// AWSAdvertisementSpec defines the desired state of AWSAdvertisement.
type AWSAdvertisementSpec struct {
	// The list of IPAddressPools to advertise via this advertisement, selected by name.
	// +optional
	IPAddressPools []string `json:"ipAddressPools,omitempty"`
	// A selector for the IPAddressPools which would get advertised via this advertisement.
	// If no IPAddressPool is selected by this or by the list, the advertisement is applied to all the IPAddressPools.
	// +optional
	IPAddressPoolSelectors []metav1.LabelSelector `json:"ipAddressPoolSelectors,omitempty"`
	// NodeSelectors allows to limit the nodes to announce as next hops for the LoadBalancer IP. When empty, all the nodes having  are announced as next hops.
	// +optional
	NodeSelectors []metav1.LabelSelector `json:"nodeSelectors,omitempty"`
}

// AWSAdvertisementStatus defines the observed state of AWSAdvertisement.
type AWSAdvertisementStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="IPAddressPools",type=string,JSONPath=`.spec.ipAddressPools`
//+kubebuilder:printcolumn:name="IPAddressPool Selectors",type=string,JSONPath=`.spec.ipAddressPoolSelectors`
//+kubebuilder:printcolumn:name="Node Selectors",type=string,JSONPath=`.spec.nodeSelectors`,priority=10

// AWSAdvertisement allows to advertise the LoadBalancer IPs provided
// by the selected pools by attaching it to an ENI of the EC2 instance.
type AWSAdvertisement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AWSAdvertisementSpec   `json:"spec,omitempty"`
	Status AWSAdvertisementStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AWSAdvertisementList contains a list of AWSAdvertisement.
type AWSAdvertisementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSAdvertisement `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AWSAdvertisement{}, &AWSAdvertisementList{})
}
