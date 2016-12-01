// +build !ignore_autogenerated_openshift

// This file was autogenerated by deepcopy-gen. Do not edit it manually!

package v1

import (
	api "k8s.io/kubernetes/pkg/api"
	unversioned "k8s.io/kubernetes/pkg/api/unversioned"
	api_v1 "k8s.io/kubernetes/pkg/api/v1"
	conversion "k8s.io/kubernetes/pkg/conversion"
)

func init() {
	if err := api.Scheme.AddGeneratedDeepCopyFuncs(
		DeepCopy_v1_ClusterNetwork,
		DeepCopy_v1_ClusterNetworkList,
		DeepCopy_v1_EgressNetworkPolicy,
		DeepCopy_v1_EgressNetworkPolicyList,
		DeepCopy_v1_EgressNetworkPolicyPeer,
		DeepCopy_v1_EgressNetworkPolicyRule,
		DeepCopy_v1_EgressNetworkPolicySpec,
		DeepCopy_v1_HostSubnet,
		DeepCopy_v1_HostSubnetList,
		DeepCopy_v1_NetNamespace,
		DeepCopy_v1_NetNamespaceList,
	); err != nil {
		// if one of the deep copy functions is malformed, detect it immediately.
		panic(err)
	}
}

func DeepCopy_v1_ClusterNetwork(in ClusterNetwork, out *ClusterNetwork, c *conversion.Cloner) error {
	if err := unversioned.DeepCopy_unversioned_TypeMeta(in.TypeMeta, &out.TypeMeta, c); err != nil {
		return err
	}
	if err := api_v1.DeepCopy_v1_ObjectMeta(in.ObjectMeta, &out.ObjectMeta, c); err != nil {
		return err
	}
	out.Network = in.Network
	out.HostSubnetLength = in.HostSubnetLength
	out.ServiceNetwork = in.ServiceNetwork
	out.PluginName = in.PluginName
	return nil
}

func DeepCopy_v1_ClusterNetworkList(in ClusterNetworkList, out *ClusterNetworkList, c *conversion.Cloner) error {
	if err := unversioned.DeepCopy_unversioned_TypeMeta(in.TypeMeta, &out.TypeMeta, c); err != nil {
		return err
	}
	if err := unversioned.DeepCopy_unversioned_ListMeta(in.ListMeta, &out.ListMeta, c); err != nil {
		return err
	}
	if in.Items != nil {
		in, out := in.Items, &out.Items
		*out = make([]ClusterNetwork, len(in))
		for i := range in {
			if err := DeepCopy_v1_ClusterNetwork(in[i], &(*out)[i], c); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

func DeepCopy_v1_EgressNetworkPolicy(in EgressNetworkPolicy, out *EgressNetworkPolicy, c *conversion.Cloner) error {
	if err := unversioned.DeepCopy_unversioned_TypeMeta(in.TypeMeta, &out.TypeMeta, c); err != nil {
		return err
	}
	if err := api_v1.DeepCopy_v1_ObjectMeta(in.ObjectMeta, &out.ObjectMeta, c); err != nil {
		return err
	}
	if err := DeepCopy_v1_EgressNetworkPolicySpec(in.Spec, &out.Spec, c); err != nil {
		return err
	}
	return nil
}

func DeepCopy_v1_EgressNetworkPolicyList(in EgressNetworkPolicyList, out *EgressNetworkPolicyList, c *conversion.Cloner) error {
	if err := unversioned.DeepCopy_unversioned_TypeMeta(in.TypeMeta, &out.TypeMeta, c); err != nil {
		return err
	}
	if err := unversioned.DeepCopy_unversioned_ListMeta(in.ListMeta, &out.ListMeta, c); err != nil {
		return err
	}
	if in.Items != nil {
		in, out := in.Items, &out.Items
		*out = make([]EgressNetworkPolicy, len(in))
		for i := range in {
			if err := DeepCopy_v1_EgressNetworkPolicy(in[i], &(*out)[i], c); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

func DeepCopy_v1_EgressNetworkPolicyPeer(in EgressNetworkPolicyPeer, out *EgressNetworkPolicyPeer, c *conversion.Cloner) error {
	out.CIDRSelector = in.CIDRSelector
	return nil
}

func DeepCopy_v1_EgressNetworkPolicyRule(in EgressNetworkPolicyRule, out *EgressNetworkPolicyRule, c *conversion.Cloner) error {
	out.Type = in.Type
	if err := DeepCopy_v1_EgressNetworkPolicyPeer(in.To, &out.To, c); err != nil {
		return err
	}
	return nil
}

func DeepCopy_v1_EgressNetworkPolicySpec(in EgressNetworkPolicySpec, out *EgressNetworkPolicySpec, c *conversion.Cloner) error {
	if in.Egress != nil {
		in, out := in.Egress, &out.Egress
		*out = make([]EgressNetworkPolicyRule, len(in))
		for i := range in {
			if err := DeepCopy_v1_EgressNetworkPolicyRule(in[i], &(*out)[i], c); err != nil {
				return err
			}
		}
	} else {
		out.Egress = nil
	}
	return nil
}

func DeepCopy_v1_HostSubnet(in HostSubnet, out *HostSubnet, c *conversion.Cloner) error {
	if err := unversioned.DeepCopy_unversioned_TypeMeta(in.TypeMeta, &out.TypeMeta, c); err != nil {
		return err
	}
	if err := api_v1.DeepCopy_v1_ObjectMeta(in.ObjectMeta, &out.ObjectMeta, c); err != nil {
		return err
	}
	out.Host = in.Host
	out.HostIP = in.HostIP
	out.Subnet = in.Subnet
	return nil
}

func DeepCopy_v1_HostSubnetList(in HostSubnetList, out *HostSubnetList, c *conversion.Cloner) error {
	if err := unversioned.DeepCopy_unversioned_TypeMeta(in.TypeMeta, &out.TypeMeta, c); err != nil {
		return err
	}
	if err := unversioned.DeepCopy_unversioned_ListMeta(in.ListMeta, &out.ListMeta, c); err != nil {
		return err
	}
	if in.Items != nil {
		in, out := in.Items, &out.Items
		*out = make([]HostSubnet, len(in))
		for i := range in {
			if err := DeepCopy_v1_HostSubnet(in[i], &(*out)[i], c); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}

func DeepCopy_v1_NetNamespace(in NetNamespace, out *NetNamespace, c *conversion.Cloner) error {
	if err := unversioned.DeepCopy_unversioned_TypeMeta(in.TypeMeta, &out.TypeMeta, c); err != nil {
		return err
	}
	if err := api_v1.DeepCopy_v1_ObjectMeta(in.ObjectMeta, &out.ObjectMeta, c); err != nil {
		return err
	}
	out.NetName = in.NetName
	out.NetID = in.NetID
	return nil
}

func DeepCopy_v1_NetNamespaceList(in NetNamespaceList, out *NetNamespaceList, c *conversion.Cloner) error {
	if err := unversioned.DeepCopy_unversioned_TypeMeta(in.TypeMeta, &out.TypeMeta, c); err != nil {
		return err
	}
	if err := unversioned.DeepCopy_unversioned_ListMeta(in.ListMeta, &out.ListMeta, c); err != nil {
		return err
	}
	if in.Items != nil {
		in, out := in.Items, &out.Items
		*out = make([]NetNamespace, len(in))
		for i := range in {
			if err := DeepCopy_v1_NetNamespace(in[i], &(*out)[i], c); err != nil {
				return err
			}
		}
	} else {
		out.Items = nil
	}
	return nil
}