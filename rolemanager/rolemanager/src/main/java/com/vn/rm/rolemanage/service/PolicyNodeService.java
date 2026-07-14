package com.vn.rm.rolemanage.service;

import com.vn.rm.rolemanage.constants.PolicyConstants;
import com.vn.rm.rolemanage.userinterfacefragment.PolicyGroupNode;
import io.jmix.security.model.ResourcePolicyEffect;
import io.jmix.security.model.ResourcePolicyModel;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for policy node tree operations
 * Handles node indexing, compression, state management, and leaf operations
 */
@Component("rm_PolicyNodeService")
public class PolicyNodeService {

    // Index for fast leaf lookup
    private final Map<String, List<PolicyGroupNode>> leafIndex = new ConcurrentHashMap<>();

    /**
     * Index all leaves in the tree for state synchronization
     */
    public void indexLeaves(@NonNull PolicyGroupNode node) {
        if (node.isLeaf()) {
            String key = buildLeafKey(node);
            if (key != null) {
                leafIndex.computeIfAbsent(key, k -> new ArrayList<>()).add(node);
            }
        }

        for (PolicyGroupNode child : node.getChildren()) {
            indexLeaves(child);
        }
    }

    /**
     * Clear the leaf index
     */
    public void clearIndex() {
        leafIndex.clear();
    }

    /**
     * Get all indexed leaves
     */
    @NonNull
    public Collection<PolicyGroupNode> getAllIndexedLeaves() {
        List<PolicyGroupNode> result = new ArrayList<>();
        for (List<PolicyGroupNode> list : leafIndex.values()) {
            result.addAll(list);
        }
        return result;
    }

    /**
     * Get nodes by key
     */
    @Nullable
    public List<PolicyGroupNode> getNodesByKey(@Nullable String key) {
        if (key == null) {
            return null;
        }
        return leafIndex.get(key);
    }

    /**
     * Get the leaf index (for external access)
     */
    @NonNull
    public Map<String, List<PolicyGroupNode>> getLeafIndex() {
        return leafIndex;
    }

    /**
     * Build unique key for leaf using resource + action
     */
    @Nullable
    public String buildLeafKey(@NonNull PolicyGroupNode node) {
        return buildLeafKey(node.getResource(), node.getAction(), node.getType());
    }

    /**
     * Build leaf key from components
     * Returns "resource|action" for synchronizing leaves
     */
    @Nullable
    public String buildLeafKey(@Nullable String resource, @Nullable String action, @Nullable String type) {
        if (resource == null || action == null) {
            return null;
        }

        // MENU has separate key to avoid conflict with SCREEN
        if (PolicyConstants.TYPE_MENU.equalsIgnoreCase(type)) {
            return resource + "|" + action.toLowerCase() + "|menu";
        }

        // SCREEN standard key
        return resource + "|" + action.toLowerCase();
    }

    /**
     * Compress tree by merging 1-to-1 folders if no leaves inside
     */
    @NonNull
    public PolicyGroupNode compress(@NonNull PolicyGroupNode node) {
        if (!node.getGroup()) {
            return node;
        }

        List<PolicyGroupNode> newChildren = new ArrayList<>();
        for (PolicyGroupNode child : node.getChildren()) {
            newChildren.add(compress(child));
        }
        node.setChildren(newChildren);

        // Don't merge if node has leaf children
        boolean hasLeaf = node.getChildren().stream().anyMatch(n -> !n.getGroup());
        if (hasLeaf) {
            return node;
        }

        // Merge 1-to-1 group
        if (node.getChildren().size() == 1 && node.getChildren().get(0).getGroup()) {
            PolicyGroupNode onlyChild = node.getChildren().get(0);
            if (!"View Access".equals(node.getName())) {
                onlyChild.setName(node.getName() + "." + onlyChild.getName());
            }
            return onlyChild;
        }

        return node;
    }

    /**
     * Apply state (allow/deny) to a leaf node
     */
    public void applyState(@NonNull PolicyGroupNode node, boolean allow) {
        if (allow) {
            node.setEffect(PolicyConstants.EFFECT_ALLOW);
            node.setAllow(true);
            node.setDeny(false);
        } else {
            // DENY → only display in UI, don't save to DB
            node.setEffect(null);
            node.setAllow(false);
            node.setDeny(true);
        }
    }

    /**
     * Collect all ALLOW leaves from tree
     */
    @NonNull
    public List<ResourcePolicyModel> collectLeaves(@NonNull PolicyGroupNode node) {
        List<ResourcePolicyModel> result = new ArrayList<>();

        if (node.isLeaf() && PolicyConstants.EFFECT_ALLOW.equals(node.getEffect())) {
            ResourcePolicyModel policy = new ResourcePolicyModel();
            policy.setId(UUID.randomUUID());
            policy.setType(node.getType());
            policy.setResource(node.getResource());
            policy.setAction(node.getAction());
            policy.setEffect(PolicyConstants.EFFECT_ALLOW);
            result.add(policy);
        }

        for (PolicyGroupNode child : node.getChildren()) {
            result.addAll(collectLeaves(child));
        }

        return result;
    }

    /**
     * Check if view is locked by menu (has at least one menu ALLOW)
     */
    public boolean isViewLockedByMenu(@NonNull PolicyGroupNode viewNode) {
        if (!PolicyConstants.TYPE_SCREEN.equalsIgnoreCase(viewNode.getType())) {
            return false;
        }

        String keyScreen = buildLeafKey(viewNode.getResource(), viewNode.getAction(), PolicyConstants.TYPE_SCREEN);
        String keyMenu = buildLeafKey(viewNode.getResource(), viewNode.getAction(), PolicyConstants.TYPE_MENU);

        List<PolicyGroupNode> linked = new ArrayList<>();
        List<PolicyGroupNode> screenNodes = getNodesByKey(keyScreen);
        List<PolicyGroupNode> menuNodes = getNodesByKey(keyMenu);

        if (screenNodes != null) linked.addAll(screenNodes);
        if (menuNodes != null) linked.addAll(menuNodes);

        if (linked.isEmpty()) {
            return false;
        }

        // Locked if at least one menu has ALLOW effect
        return linked.stream().anyMatch(n ->
                PolicyConstants.TYPE_MENU.equalsIgnoreCase(n.getType()) &&
                        PolicyConstants.EFFECT_ALLOW.equals(n.getEffect())
        );
    }

    /**
     * Synchronize linked leaves (MENU ↔ VIEW)
     *
     * Logic:
     * - MENU tick Allow → force VIEW Allow
     * - MENU tick Deny → VIEW goes to blank (no forced deny)
     * - VIEW tick Allow/Deny → only sync VIEW ↔ VIEW (not MENU)
     */
    public void syncLinkedLeaves(@NonNull PolicyGroupNode node, boolean allow) {
        boolean isMenu = PolicyConstants.TYPE_MENU.equalsIgnoreCase(node.getType());
        boolean isView = PolicyConstants.TYPE_SCREEN.equalsIgnoreCase(node.getType());

        String keyScreen = buildLeafKey(node.getResource(), node.getAction(), PolicyConstants.TYPE_SCREEN);
        String keyMenu = buildLeafKey(node.getResource(), node.getAction(), PolicyConstants.TYPE_MENU);

        // Gather all related nodes
        List<PolicyGroupNode> linked = new ArrayList<>();
        List<PolicyGroupNode> screenNodes = getNodesByKey(keyScreen);
        List<PolicyGroupNode> menuNodes = getNodesByKey(keyMenu);

        if (screenNodes != null) linked.addAll(screenNodes);
        if (menuNodes != null) linked.addAll(menuNodes);

        if (linked.isEmpty()) {
            applyState(node, allow);
            return;
        }

        // CASE 1: MENU → affects VIEW
        if (isMenu) {
            for (PolicyGroupNode target : linked) {
                if (PolicyConstants.TYPE_MENU.equalsIgnoreCase(target.getType())) {
                    // MENU ↔ MENU full sync
                    target.setEffect(allow ? PolicyConstants.EFFECT_ALLOW : null);
                    target.setAllow(allow);
                    target.setDeny(!allow);
                } else if (PolicyConstants.TYPE_SCREEN.equalsIgnoreCase(target.getType())) {
                    if (allow) {
                        // MENU = ALLOW → force VIEW = ALLOW
                        target.setEffect(PolicyConstants.EFFECT_ALLOW);
                        target.setAllow(true);
                        target.setDeny(false);
                    }
                    // If MENU = DENY → VIEW keeps original (no forced deny)
                }
            }
            applyState(node, allow);
            return;
        }

        // CASE 2: VIEW → only sync VIEW ↔ VIEW
        if (isView) {
            for (PolicyGroupNode target : linked) {
                if (PolicyConstants.TYPE_SCREEN.equalsIgnoreCase(target.getType())) {
                    target.setEffect(allow ? PolicyConstants.EFFECT_ALLOW : null);
                    target.setAllow(allow);
                    target.setDeny(!allow);
                }
            }
            applyState(node, allow);
            return;
        }

        // Fallback
        applyState(node, allow);
    }
}
