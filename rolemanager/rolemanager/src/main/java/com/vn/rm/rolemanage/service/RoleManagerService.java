package com.vn.rm.rolemanage.service;

import com.google.common.base.Strings;
import com.vn.rm.rolemanage.entityfragment.EntityMatrixRow;
import com.vn.rm.rolemanage.userinterfacefragment.PolicyGroupNode;
import io.jmix.core.Metadata;
import io.jmix.flowui.menu.MenuConfig;
import io.jmix.flowui.menu.MenuItem;
import io.jmix.security.model.*;
import io.jmix.security.role.ResourceRoleRepository;
import io.jmix.securityflowui.view.resourcepolicy.AttributeResourceModel;
import io.jmix.securityflowui.view.resourcepolicy.ResourcePolicyViewUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Main facade service for role management operations
 * Coordinates between specialized services for complete role management functionality
 */
@Component("rm_RoleManagerService")
public class RoleManagerService {

    private final EntityPolicyService entityPolicyService;
    private final AttributePolicyService attributePolicyService;
    private final PolicyNodeService policyNodeService;
    private final ViewMenuPolicyService viewMenuPolicyService;
    private final PolicyConverterService policyConverterService;

    private final ResourceRoleRepository resourceRoleRepository;
    private final Metadata metadata;
    private final ResourcePolicyViewUtils resourcePolicyViewUtils;

    // Current annotated role being managed
    private ResourceRoleModel annotatedRole;

    public RoleManagerService(EntityPolicyService entityPolicyService,
                             AttributePolicyService attributePolicyService,
                             PolicyNodeService policyNodeService,
                             ViewMenuPolicyService viewMenuPolicyService,
                             PolicyConverterService policyConverterService,
                             ResourceRoleRepository resourceRoleRepository,
                             Metadata metadata,
                             ResourcePolicyViewUtils resourcePolicyViewUtils) {
        this.entityPolicyService = entityPolicyService;
        this.attributePolicyService = attributePolicyService;
        this.policyNodeService = policyNodeService;
        this.viewMenuPolicyService = viewMenuPolicyService;
        this.policyConverterService = policyConverterService;
        this.resourceRoleRepository = resourceRoleRepository;
        this.metadata = metadata;
        this.resourcePolicyViewUtils = resourcePolicyViewUtils;
    }

    // ========================================================================
    // Entity Matrix Operations
    // ========================================================================

    /**
     * Create skeleton entity matrix (without policies applied)
     */
    @NonNull
    public List<EntityMatrixRow> createMatrixEntity() {
        return entityPolicyService.createMatrixEntity();
    }

    /**
     * Apply entity policies to matrix rows
     */
    public void updateEntityMatrix(@NonNull List<EntityMatrixRow> rows,
                                   @Nullable Collection<ResourcePolicyModel> policies,
                                   @NonNull Map<String, List<AttributeResourceModel>> attrCache) {
        if (rows.isEmpty()) {
            return;
        }

        // Build attribute policy map
        Map<String, Map<String, Set<String>>> attrPolicyMap = attributePolicyService.buildAttrPolicyMap(policies);

        // Apply entity policies
        entityPolicyService.applyEntityPolicies(rows, policies);

        // Apply attribute policies
        for (EntityMatrixRow row : rows) {
            String entity = row.getEntityName();

            // Build or get cached attribute rows
            List<AttributeResourceModel> attrRows;
            if (!attrCache.containsKey(entity)) {
                attrRows = attributePolicyService.buildAttrRowsForEntity(entity);
                attrCache.put(entity, attrRows);
            } else {
                attrRows = attrCache.get(entity);
            }

            // Apply policies to attribute rows
            Map<String, Set<String>> entityAttrs = attrPolicyMap.getOrDefault(entity, Collections.emptyMap());
            attributePolicyService.applyAttrPoliciesToRows(attrRows, entityAttrs);

            // Update summary
            String summary = attributePolicyService.computeAttrSummaryFromRows(attrRows);
            row.setAttributes(summary);
        }
    }

    /**
     * Sync allowAll flag based on CRUD permissions
     */
    public void syncAllowAll(@NonNull EntityMatrixRow row) {
        entityPolicyService.syncAllowAll(row);
    }

    /**
     * Build policies from entity matrix and attribute cache
     */
    @NonNull
    public List<ResourcePolicyModel> buildPoliciesFromMatrix(@NonNull List<EntityMatrixRow> entityRows,
                                                             @NonNull Map<String, List<AttributeResourceModel>> attrCache) {
        List<ResourcePolicyModel> result = new ArrayList<>();

        // Build entity policies
        result.addAll(entityPolicyService.buildPoliciesFromMatrix(entityRows));

        // Build attribute policies for each entity
        for (EntityMatrixRow row : entityRows) {
            String entity = row.getEntityName();
            List<AttributeResourceModel> attrs = attrCache.getOrDefault(entity, Collections.emptyList());

            if (!attrs.isEmpty()) {
                result.addAll(attributePolicyService.buildAttrPolicies(entity, attrs));
            }
        }

        return result;
    }

    /**
     * Update entity attributes summary
     */
    public void updateEntityAttributesSummary(@NonNull String entityName,
                                            @NonNull List<EntityMatrixRow> entityRows,
                                            @NonNull List<AttributeResourceModel> currentAttrRows,
                                            @NonNull Map<String, List<AttributeResourceModel>> attrCache) {
        if (Strings.isNullOrEmpty(entityName)) {
            return;
        }

        // Update cache
        attrCache.put(entityName, new ArrayList<>(currentAttrRows));

        // Update summary in entity row
        String summary = attributePolicyService.computeAttrSummaryFromRows(currentAttrRows);
        entityRows.stream()
                .filter(r -> entityName.equals(r.getEntityName()))
                .findFirst()
                .ifPresent(row -> row.setAttributes(summary));
    }

    // ========================================================================
    // Attribute Operations
    // ========================================================================

    /**
     * Build attribute rows for an entity
     */
    @NonNull
    public List<AttributeResourceModel> buildAttrRowsForEntity(@NonNull String entityName) {
        return attributePolicyService.buildAttrRowsForEntity(entityName);
    }

    /**
     * Compute attribute summary from rows
     */
    @Nullable
    public String computeAttrSummaryFromRows(@Nullable List<AttributeResourceModel> rows) {
        return attributePolicyService.computeAttrSummaryFromRows(rows);
    }

    // ========================================================================
    // Policy Node Operations
    // ========================================================================

    /**
     * Index all leaves in tree
     */
    public void indexLeaves(@NonNull PolicyGroupNode node) {
        policyNodeService.indexLeaves(node);
    }

    /**
     * Clear leaf index
     */
    public void clearIndex() {
        policyNodeService.clearIndex();
    }

    /**
     * Get leaf index
     */
    @NonNull
    public Map<String, List<PolicyGroupNode>> getLeafIndex() {
        return policyNodeService.getLeafIndex();
    }

    /**
     * Get all indexed leaves
     */
    @NonNull
    public Collection<PolicyGroupNode> getAllIndexedLeaves() {
        return policyNodeService.getAllIndexedLeaves();
    }

    /**
     * Get nodes by key
     */
    @Nullable
    public List<PolicyGroupNode> getNodesByKey(@Nullable String key) {
        return policyNodeService.getNodesByKey(key);
    }

    /**
     * Build leaf key from node
     */
    @Nullable
    public String buildLeafKey(@NonNull PolicyGroupNode node) {
        return policyNodeService.buildLeafKey(node);
    }

    /**
     * Build leaf key from components
     */
    @Nullable
    public String buildLeafKey(@Nullable String resource, @Nullable String action, @Nullable String type) {
        return policyNodeService.buildLeafKey(resource, action, type);
    }

    /**
     * Compress policy tree
     */
    @NonNull
    public PolicyGroupNode compress(@NonNull PolicyGroupNode node) {
        return policyNodeService.compress(node);
    }

    /**
     * Sync linked leaves (MENU ↔ VIEW)
     */
    public void syncLinkedLeaves(@NonNull PolicyGroupNode node, boolean allow) {
        policyNodeService.syncLinkedLeaves(node, allow);
    }

    /**
     * Check if view is locked by menu
     */
    public boolean isViewLockedByMenu(@NonNull PolicyGroupNode viewNode) {
        return policyNodeService.isViewLockedByMenu(viewNode);
    }

    /**
     * Apply state to leaf
     */
    public void applyState(@NonNull PolicyGroupNode node, boolean allow) {
        policyNodeService.applyState(node, allow);
    }

    /**
     * Collect all ALLOW leaves from tree
     */
    @NonNull
    public List<ResourcePolicyModel> collectLeaves(@NonNull PolicyGroupNode node) {
        return policyNodeService.collectLeaves(node);
    }

    // ========================================================================
    // View/Menu Operations
    // ========================================================================

    /**
     * Build view menu map
     */
    @NonNull
    public Map<String, List<MenuItem>> buildViewMenuMap() {
        return viewMenuPolicyService.buildViewMenuMap();
    }

    /**
     * Scan fragments
     */
    @NonNull
    public Map<String, String> scanFragments() {
        return viewMenuPolicyService.scanFragments();
    }

    /**
     * Build menu tree
     */
    public void buildMenuTree(@NonNull PolicyGroupNode menuRoot) {
        viewMenuPolicyService.buildMenuTree(menuRoot);
    }

    /**
     * Build views tree (uses current annotated role)
     */
    public void buildViewsTree(@NonNull PolicyGroupNode root,
                              @NonNull Map<String, List<MenuItem>> viewMenuMap) {
        ResourceRoleModel currentAnnotatedRole = annotatedRole != null ? annotatedRole : new ResourceRoleModel();
        viewMenuPolicyService.buildViewsTree(root, viewMenuMap, currentAnnotatedRole);
    }

    /**
     * Build views tree with explicit annotated role
     */
    public void buildViewsTree(@NonNull PolicyGroupNode root,
                              @NonNull Map<String, List<MenuItem>> viewMenuMap,
                              @NonNull ResourceRoleModel annotatedRole) {
        viewMenuPolicyService.buildViewsTree(root, viewMenuMap, annotatedRole);
    }

    // ========================================================================
    // Converter Operations
    // ========================================================================

    /**
     * Set annotated role
     */
    public void setAnnotatedRole(@Nullable ResourceRoleModel role) {
        this.annotatedRole = role;
        policyConverterService.setAnnotatedRole(role);
    }

    /**
     * Get annotated role
     */
    @Nullable
    public ResourceRoleModel getAnnotatedRole() {
        return annotatedRole;
    }

    /**
     * Convert annotated role to model
     */
    @NonNull
    public ResourceRoleModel convertAnnotatedToModel(@NonNull ResourceRole runtimeRole) {
        return policyConverterService.convertAnnotatedToModel(runtimeRole);
    }

    /**
     * Check if view is annotated
     */
    public boolean isAnnotatedView(@NonNull String viewId) {
        return policyConverterService.isAnnotatedView(viewId);
    }

    /**
     * Check if menu is annotated
     */
    public boolean isAnnotatedMenu(@NonNull String viewId) {
        return policyConverterService.isAnnotatedMenu(viewId);
    }

    /**
     * Create policy
     */
    @NonNull
    public ResourcePolicyModel createPolicy(@NonNull String type, @NonNull String resource, @NonNull String action) {
        return policyConverterService.createPolicy(type, resource, action);
    }

    /**
     * Get role by code
     */
    @Nullable
    public ResourceRole getRoleByCode(@NonNull String code) {
        return resourceRoleRepository.findRoleByCode(code);
    }

    // ========================================================================
    // Optimization
    // ========================================================================

    /**
     * Optimize entity policies by removing redundant ones
     */
    @NonNull
    public List<ResourcePolicyModel> optimizeEntityPolicies(@NonNull List<ResourcePolicyModel> inputPolicies) {
        return entityPolicyService.optimizeEntityPolicies(inputPolicies);
    }
}
