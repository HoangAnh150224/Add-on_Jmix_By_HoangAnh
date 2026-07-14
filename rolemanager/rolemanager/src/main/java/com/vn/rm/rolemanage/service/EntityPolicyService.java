package com.vn.rm.rolemanage.service;

import com.vn.rm.rolemanage.constants.PolicyConstants;
import com.vn.rm.rolemanage.entityfragment.EntityMatrixRow;
import io.jmix.core.Metadata;
import io.jmix.flowui.fragment.FragmentDescriptor;
import io.jmix.security.model.ResourcePolicyEffect;
import io.jmix.security.model.ResourcePolicyModel;
import io.jmix.security.model.ResourcePolicyType;
import io.jmix.securityflowui.view.resourcepolicy.EntityPolicyAction;
import io.jmix.securityflowui.view.resourcepolicy.ResourcePolicyViewUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for entity-related policy operations
 * Handles entity matrix creation, policy application, and policy building
 */
@Component("rm_EntityPolicyService")
public class EntityPolicyService {

    private final Metadata metadata;
    private final ResourcePolicyViewUtils resourcePolicyViewUtils;

    public EntityPolicyService(Metadata metadata,
                              ResourcePolicyViewUtils resourcePolicyViewUtils) {
        this.metadata = metadata;
        this.resourcePolicyViewUtils = resourcePolicyViewUtils;
    }

    /**
     * Create skeleton entity matrix (without policies applied)
     */
    @NonNull
    public List<EntityMatrixRow> createMatrixEntity() {
        return resourcePolicyViewUtils.getEntityOptionsMap().entrySet().stream()
                .filter(e -> !PolicyConstants.WILDCARD_RESOURCE.equals(e.getKey()))
                .map(e -> {
                    EntityMatrixRow row = metadata.create(EntityMatrixRow.class);
                    row.setEntityName(e.getKey());
                    row.setEntityCaption(e.getValue());
                    return row;
                })
                .collect(Collectors.toList());
    }

    /**
     * Apply entity policies to matrix rows
     */
    public void applyEntityPolicies(@NonNull List<EntityMatrixRow> rows,
                                   @Nullable Collection<ResourcePolicyModel> policies) {
        if (rows.isEmpty()) {
            return;
        }

        Map<String, Set<String>> entityPolicyMap = buildEntityPolicyMap(policies);
        Set<String> globalActions = entityPolicyMap.getOrDefault(PolicyConstants.WILDCARD_RESOURCE, Collections.emptySet());

        for (EntityMatrixRow row : rows) {
            String entity = row.getEntityName();
            Set<String> actions = entityPolicyMap.getOrDefault(entity, Collections.emptySet());

            // Merge entity-specific and global (*) permissions
            row.setCanCreate(hasAction(actions, globalActions, PolicyConstants.ACT_CREATE));
            row.setCanRead(hasAction(actions, globalActions, PolicyConstants.ACT_READ));
            row.setCanUpdate(hasAction(actions, globalActions, PolicyConstants.ACT_UPDATE));
            row.setCanDelete(hasAction(actions, globalActions, PolicyConstants.ACT_DELETE));

            syncAllowAll(row);
        }
    }

    /**
     * Sync allowAll flag based on CRUD permissions
     * allowAll = true only if all CRUD are true
     */
    public void syncAllowAll(@NonNull EntityMatrixRow row) {
        boolean all = Boolean.TRUE.equals(row.getCanCreate())
                && Boolean.TRUE.equals(row.getCanRead())
                && Boolean.TRUE.equals(row.getCanUpdate())
                && Boolean.TRUE.equals(row.getCanDelete());
        row.setAllowAll(all);
    }

    /**
     * Build entity policies from matrix rows
     */
    @NonNull
    public List<ResourcePolicyModel> buildPoliciesFromMatrix(@NonNull List<EntityMatrixRow> entityRows) {
        List<ResourcePolicyModel> result = new ArrayList<>();

        // Filter valid rows
        List<EntityMatrixRow> activeRows = entityRows.stream()
                .filter(r -> r.getEntityName() != null
                        && !r.getEntityName().isBlank()
                        && !PolicyConstants.WILDCARD_RESOURCE.equals(r.getEntityName()))
                .collect(Collectors.toList());

        if (activeRows.isEmpty()) {
            return result;
        }

        // Check for "All Entities" (*) conditions
        WildcardState wildcardState = analyzeWildcardState(activeRows);

        // Add wildcard policies if applicable
        addWildcardPolicies(result, wildcardState);

        // Add entity-specific policies (excluding those covered by wildcard)
        for (EntityMatrixRow row : activeRows) {
            String entity = row.getEntityName();
            boolean allowAll = Boolean.TRUE.equals(row.getAllowAll());

            addEntityPolicyIfNeeded(result, wildcardState.allCreate, allowAll, row.getCanCreate(), entity, PolicyConstants.ACT_CREATE);
            addEntityPolicyIfNeeded(result, wildcardState.allRead, allowAll, row.getCanRead(), entity, PolicyConstants.ACT_READ);
            addEntityPolicyIfNeeded(result, wildcardState.allUpdate, allowAll, row.getCanUpdate(), entity, PolicyConstants.ACT_UPDATE);
            addEntityPolicyIfNeeded(result, wildcardState.allDelete, allowAll, row.getCanDelete(), entity, PolicyConstants.ACT_DELETE);
        }

        return result;
    }

    /**
     * Optimize entity policies by removing redundant ones (when wildcard exists)
     */
    @NonNull
    public List<ResourcePolicyModel> optimizeEntityPolicies(@NonNull List<ResourcePolicyModel> inputPolicies) {
        Set<String> wildcardActions = extractWildcardActions(inputPolicies);

        if (wildcardActions.isEmpty()) {
            return new ArrayList<>(inputPolicies);
        }

        return inputPolicies.stream()
                .filter(p -> !isRedundantEntityPolicy(p, wildcardActions))
                .collect(Collectors.toList());
    }

    // Private helper methods

    private Map<String, Set<String>> buildEntityPolicyMap(@Nullable Collection<ResourcePolicyModel> policies) {
        Map<String, Set<String>> entityPolicyMap = new HashMap<>();

        if (policies == null) {
            return entityPolicyMap;
        }

        for (ResourcePolicyModel p : policies) {
            if (p.getResource() == null || !Objects.equals(p.getEffect(), ResourcePolicyEffect.ALLOW)) {
                continue;
            }

            if (ResourcePolicyType.ENTITY.equals(p.getType()) && p.getAction() != null) {
                entityPolicyMap
                        .computeIfAbsent(p.getResource(), k -> new HashSet<>())
                        .add(p.getAction());
            }
        }

        return entityPolicyMap;
    }

    private boolean hasAction(Set<String> entityActions, Set<String> globalActions, String action) {
        return entityActions.contains(action) || globalActions.contains(action);
    }

    private WildcardState analyzeWildcardState(List<EntityMatrixRow> activeRows) {
        return new WildcardState(
                activeRows.stream().allMatch(r -> Boolean.TRUE.equals(r.getCanCreate()) || Boolean.TRUE.equals(r.getAllowAll())),
                activeRows.stream().allMatch(r -> Boolean.TRUE.equals(r.getCanRead()) || Boolean.TRUE.equals(r.getAllowAll())),
                activeRows.stream().allMatch(r -> Boolean.TRUE.equals(r.getCanUpdate()) || Boolean.TRUE.equals(r.getAllowAll())),
                activeRows.stream().allMatch(r -> Boolean.TRUE.equals(r.getCanDelete()) || Boolean.TRUE.equals(r.getAllowAll()))
        );
    }

    private void addWildcardPolicies(List<ResourcePolicyModel> result, WildcardState state) {
        if (state.allCreate) {
            result.add(createPolicy(PolicyConstants.RESOURCE_TYPE_ENTITY, PolicyConstants.WILDCARD_RESOURCE, PolicyConstants.ACT_CREATE));
        }
        if (state.allRead) {
            result.add(createPolicy(PolicyConstants.RESOURCE_TYPE_ENTITY, PolicyConstants.WILDCARD_RESOURCE, PolicyConstants.ACT_READ));
        }
        if (state.allUpdate) {
            result.add(createPolicy(PolicyConstants.RESOURCE_TYPE_ENTITY, PolicyConstants.WILDCARD_RESOURCE, PolicyConstants.ACT_UPDATE));
        }
        if (state.allDelete) {
            result.add(createPolicy(PolicyConstants.RESOURCE_TYPE_ENTITY, PolicyConstants.WILDCARD_RESOURCE, PolicyConstants.ACT_DELETE));
        }
    }

    private void addEntityPolicyIfNeeded(List<ResourcePolicyModel> result, boolean hasWildcard,
                                       boolean allowAll, Boolean canAction, String entity, String action) {
        if (!hasWildcard && (allowAll || Boolean.TRUE.equals(canAction))) {
            result.add(createPolicy(PolicyConstants.RESOURCE_TYPE_ENTITY, entity, action));
        }
    }

    private ResourcePolicyModel createPolicy(String type, String resource, String action) {
        ResourcePolicyModel policy = metadata.create(ResourcePolicyModel.class);
        policy.setType(type);
        policy.setResource(resource);
        policy.setAction(action);
        policy.setEffect(ResourcePolicyEffect.ALLOW);
        policy.setPolicyGroup(PolicyConstants.WILDCARD_RESOURCE.equals(resource) ? null : resource);
        return policy;
    }

    private Set<String> extractWildcardActions(List<ResourcePolicyModel> policies) {
        return policies.stream()
                .filter(p -> PolicyConstants.RESOURCE_TYPE_ENTITY.equalsIgnoreCase(p.getType())
                        && PolicyConstants.WILDCARD_RESOURCE.equals(p.getResource())
                        && p.getAction() != null)
                .map(p -> p.getAction().trim().toLowerCase())
                .collect(Collectors.toSet());
    }

    private boolean isRedundantEntityPolicy(ResourcePolicyModel policy, Set<String> wildcardActions) {
        if (!PolicyConstants.RESOURCE_TYPE_ENTITY.equalsIgnoreCase(policy.getType())) {
            return false;
        }

        String resource = Objects.toString(policy.getResource(), "").trim();
        if (PolicyConstants.WILDCARD_RESOURCE.equals(resource)) {
            return false; // Keep wildcard policies
        }

        String action = Objects.toString(policy.getAction(), "").trim().toLowerCase();
        return wildcardActions.contains(action);
    }

    /**
     * Internal record to track wildcard state
     */
    private record WildcardState(
            boolean allCreate,
            boolean allRead,
            boolean allUpdate,
            boolean allDelete
    ) {}
}
