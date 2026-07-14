package com.vn.rm.rolemanage.service;

import com.vn.rm.rolemanage.constants.PolicyConstants;
import io.jmix.core.Metadata;
import io.jmix.security.model.*;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for converting between different policy model representations
 * Handles annotated role to model conversion and policy creation
 */
@Component("rm_PolicyConverterService")
public class PolicyConverterService {

    private final Metadata metadata;

    // Cached annotated role for checking annotations
    private ResourceRoleModel annotatedRole;

    public PolicyConverterService(Metadata metadata) {
        this.metadata = metadata;
    }

    /**
     * Set the current annotated role for reference
     */
    public void setAnnotatedRole(@Nullable ResourceRoleModel role) {
        this.annotatedRole = role;
    }

    /**
     * Get the current annotated role
     */
    @Nullable
    public ResourceRoleModel getAnnotatedRole() {
        return annotatedRole;
    }

    /**
     * Convert annotated runtime role to model
     */
    @NonNull
    public ResourceRoleModel convertAnnotatedToModel(@NonNull ResourceRole runtimeRole) {
        ResourceRoleModel model = new ResourceRoleModel();
        model.setCode(runtimeRole.getCode());
        model.setName(runtimeRole.getName());
        model.setSource(RoleSourceType.ANNOTATED_CLASS);
        model.setScopes(runtimeRole.getScopes());

        Set<ResourcePolicyModel> policies = runtimeRole.getResourcePolicies().stream()
                .map(p -> {
                    ResourcePolicyModel m = metadata.create(ResourcePolicyModel.class);
                    m.setType(p.getType());
                    m.setResource(p.getResource());
                    m.setAction(p.getAction());
                    m.setEffect(p.getEffect());

                    // Auto-set policy group if empty
                    String group = p.getPolicyGroup();
                    if (group == null || group.isBlank()) {
                        group = p.getResource();
                    }
                    m.setPolicyGroup(group);

                    return m;
                })
                .collect(Collectors.toSet());

        model.setResourcePolicies(new ArrayList<>(policies));
        return model;
    }

    /**
     * Create a new policy model
     */
    @NonNull
    public ResourcePolicyModel createPolicy(@NonNull String type,
                                           @NonNull String resource,
                                           @NonNull String action) {
        ResourcePolicyModel policy = metadata.create(ResourcePolicyModel.class);
        policy.setType(type);
        policy.setResource(resource);
        policy.setAction(action);
        policy.setEffect(ResourcePolicyEffect.ALLOW);
        policy.setPolicyGroup(determinePolicyGroup(resource));
        return policy;
    }

    /**
     * Create a new policy model with explicit effect (as String)
     */
    @NonNull
    public ResourcePolicyModel createPolicy(@NonNull String type,
                                           @NonNull String resource,
                                           @NonNull String action,
                                           @NonNull String effect) {
        ResourcePolicyModel policy = metadata.create(ResourcePolicyModel.class);
        policy.setType(type);
        policy.setResource(resource);
        policy.setAction(action);
        policy.setEffect(effect);
        policy.setPolicyGroup(determinePolicyGroup(resource));
        return policy;
    }

    /**
     * Determine policy group from resource
     */
    @NonNull
    public String determinePolicyGroup(@NonNull String resource) {
        if (resource.endsWith(PolicyConstants.WILDCARD_RESOURCE)) {
            return null;
        }
        return resource;
    }

    /**
     * Check if a view is annotated
     */
    public boolean isAnnotatedView(@NonNull String viewId) {
        if (annotatedRole == null) {
            return false;
        }

        return annotatedRole.getResourcePolicies().stream()
                .anyMatch(p ->
                        ResourcePolicyEffect.ALLOW.equals(p.getEffect())
                                && PolicyConstants.RESOURCE_TYPE_SCREEN.equalsIgnoreCase(p.getType())
                                && (PolicyConstants.WILDCARD_RESOURCE.equals(p.getResource()) ||
                                    Objects.equals(p.getResource(), viewId))
                );
    }

    /**
     * Check if a menu is annotated
     */
    public boolean isAnnotatedMenu(@NonNull String viewId) {
        if (annotatedRole == null) {
            return false;
        }

        return annotatedRole.getResourcePolicies().stream()
                .anyMatch(p ->
                        ResourcePolicyEffect.ALLOW.equals(p.getEffect())
                                && PolicyConstants.RESOURCE_TYPE_MENU.equalsIgnoreCase(p.getType())
                                && (PolicyConstants.WILDCARD_RESOURCE.equals(p.getResource()) ||
                                    Objects.equals(p.getResource(), viewId))
                );
    }
}
