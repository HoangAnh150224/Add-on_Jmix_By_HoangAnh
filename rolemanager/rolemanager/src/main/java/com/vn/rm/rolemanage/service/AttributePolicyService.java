package com.vn.rm.rolemanage.service;

import com.vn.rm.rolemanage.constants.PolicyConstants;
import io.jmix.core.Metadata;
import io.jmix.security.model.ResourcePolicyEffect;
import io.jmix.security.model.ResourcePolicyModel;
import io.jmix.security.model.ResourcePolicyType;
import io.jmix.securityflowui.view.resourcepolicy.AttributeResourceModel;
import io.jmix.securityflowui.view.resourcepolicy.ResourcePolicyViewUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for attribute-related policy operations
 * Handles attribute matrix creation, policy application, and attribute summary computation
 */
@Component("rm_AttributePolicyService")
public class AttributePolicyService {

    private final Metadata metadata;
    private final ResourcePolicyViewUtils resourcePolicyViewUtils;

    public AttributePolicyService(Metadata metadata,
                                  ResourcePolicyViewUtils resourcePolicyViewUtils) {
        this.metadata = metadata;
        this.resourcePolicyViewUtils = resourcePolicyViewUtils;
    }

    /**
     * Create attribute rows for an entity (without policies applied)
     */
    @NonNull
    public List<AttributeResourceModel> buildAttrRowsForEntity(@NonNull String entityName) {
        return resourcePolicyViewUtils.getEntityAttributeOptionsMap(entityName).entrySet().stream()
                .filter(e -> !PolicyConstants.WILDCARD_RESOURCE.equals(e.getKey()))
                .map(e -> {
                    AttributeResourceModel row = metadata.create(AttributeResourceModel.class);
                    row.setName(e.getKey());
                    row.setCaption(e.getValue());
                    return row;
                })
                .sorted(Comparator.comparing(AttributeResourceModel::getName, String.CASE_INSENSITIVE_ORDER))
                .collect(Collectors.toList());
    }

    /**
     * Apply attribute policies (wildcard + specific) to rows
     */
    public void applyAttrPoliciesToRows(@NonNull List<AttributeResourceModel> rows,
                                        @NonNull Map<String, Set<String>> attrPolicies) {
        Set<String> wildcardActions = attrPolicies.getOrDefault(PolicyConstants.WILDCARD_RESOURCE, Collections.emptySet());
        boolean wildView = wildcardActions.contains(PolicyConstants.ACT_ATTR_VIEW);
        boolean wildModify = wildcardActions.contains(PolicyConstants.ACT_ATTR_MODIFY);

        for (AttributeResourceModel row : rows) {
            Set<String> specificActions = attrPolicies.getOrDefault(row.getName(), Collections.emptySet());
            row.setView(wildView || specificActions.contains(PolicyConstants.ACT_ATTR_VIEW));
            row.setModify(wildModify || specificActions.contains(PolicyConstants.ACT_ATTR_MODIFY));
        }
    }

    /**
     * Build attribute policy map from resource policies
     */
    @NonNull
    public Map<String, Map<String, Set<String>>> buildAttrPolicyMap(@Nullable Collection<ResourcePolicyModel> policies) {
        Map<String, Map<String, Set<String>>> attrPolicyMap = new HashMap<>();

        if (policies == null) {
            return attrPolicyMap;
        }

        for (ResourcePolicyModel p : policies) {
            if (p.getResource() == null || !Objects.equals(p.getEffect(), ResourcePolicyEffect.ALLOW)) {
                continue;
            }

            if (ResourcePolicyType.ENTITY_ATTRIBUTE.equals(p.getType()) && p.getAction() != null) {
                String resource = p.getResource();
                int dotIndex = resource.lastIndexOf('.');
                if (dotIndex > 0) {
                    String entity = resource.substring(0, dotIndex);
                    String attr = resource.substring(dotIndex + 1);
                    attrPolicyMap
                            .computeIfAbsent(entity, k -> new HashMap<>())
                            .computeIfAbsent(attr, k -> new HashSet<>())
                            .add(p.getAction());
                }
            }
        }

        return attrPolicyMap;
    }

    /**
     * Compute attribute summary: null / "*" / "attr1, attr2, ..."
     */
    @Nullable
    public String computeAttrSummaryFromRows(@Nullable List<AttributeResourceModel> rows) {
        if (rows == null || rows.isEmpty()) {
            return null;
        }

        boolean allView = true;
        boolean allModify = true;
        List<String> selected = new ArrayList<>();

        for (AttributeResourceModel r : rows) {
            boolean v = Boolean.TRUE.equals(r.getView());
            boolean m = Boolean.TRUE.equals(r.getModify());

            if (!v) allView = false;
            if (!m) allModify = false;

            if (v || m) {
                selected.add(r.getName());
            }
        }

        if (allView || allModify) {
            return PolicyConstants.WILDCARD_RESOURCE;
        }
        if (selected.isEmpty()) {
            return null;
        }

        selected.sort(String.CASE_INSENSITIVE_ORDER);
        return String.join(", ", selected);
    }

    /**
     * Build attribute policies from attribute cache
     */
    @NonNull
    public List<ResourcePolicyModel> buildAttrPolicies(@NonNull String entityName,
                                                       @NonNull List<AttributeResourceModel> attrs) {
        List<ResourcePolicyModel> result = new ArrayList<>();

        if (attrs.isEmpty()) {
            return result;
        }

        boolean fullAttrView = attrs.stream().allMatch(a -> Boolean.TRUE.equals(a.getView()));
        boolean fullAttrModify = attrs.stream().allMatch(a -> Boolean.TRUE.equals(a.getModify()));

        // Add wildcard policies if all attributes have the same permission
        if (fullAttrView) {
            result.add(createAttrPolicy(entityName, PolicyConstants.WILDCARD_RESOURCE, PolicyConstants.ACT_ATTR_VIEW));
        }
        if (fullAttrModify) {
            result.add(createAttrPolicy(entityName, PolicyConstants.WILDCARD_RESOURCE, PolicyConstants.ACT_ATTR_MODIFY));
        }

        // If not full permissions, add individual attribute policies
        if (!fullAttrView && !fullAttrModify) {
            for (AttributeResourceModel attr : attrs) {
                if (Boolean.TRUE.equals(attr.getView())) {
                    result.add(createAttrPolicy(entityName, attr.getName(), PolicyConstants.ACT_ATTR_VIEW));
                }
                if (Boolean.TRUE.equals(attr.getModify())) {
                    result.add(createAttrPolicy(entityName, attr.getName(), PolicyConstants.ACT_ATTR_MODIFY));
                }
            }
        }

        return result;
    }

    /**
     * Update entity attributes summary and sync cache
     */
    public void updateEntityAttributesSummary(@NonNull String entityName,
                                            @NonNull List<AttributeResourceModel> currentAttrs,
                                            @NonNull Map<String, List<AttributeResourceModel>> attrCache) {
        if (entityName.isBlank()) {
            return;
        }

        attrCache.put(entityName, new ArrayList<>(currentAttrs));
    }

    private ResourcePolicyModel createAttrPolicy(String entity, String attr, String action) {
        ResourcePolicyModel policy = metadata.create(ResourcePolicyModel.class);
        policy.setType(PolicyConstants.RESOURCE_TYPE_ENTITY_ATTRIBUTE);
        policy.setResource(entity + "." + attr);
        policy.setAction(action);
        policy.setEffect(ResourcePolicyEffect.ALLOW);
        policy.setPolicyGroup(entity);
        return policy;
    }
}
