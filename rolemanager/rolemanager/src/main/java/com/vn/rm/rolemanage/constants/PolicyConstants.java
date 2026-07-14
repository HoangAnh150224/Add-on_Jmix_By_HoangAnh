package com.vn.rm.rolemanage.constants;

import io.jmix.securityflowui.view.resourcepolicy.EntityAttributePolicyAction;
import io.jmix.securityflowui.view.resourcepolicy.EntityPolicyAction;

/**
 * Constants for policy management
 * Contains all action types, resource types, and other constants used across services
 */
public final class PolicyConstants {

    private PolicyConstants() {
        // Utility class - prevent instantiation
    }

    // Entity Actions
    public static final String ACT_CREATE = EntityPolicyAction.CREATE.getId();
    public static final String ACT_READ = EntityPolicyAction.READ.getId();
    public static final String ACT_UPDATE = EntityPolicyAction.UPDATE.getId();
    public static final String ACT_DELETE = EntityPolicyAction.DELETE.getId();

    // Attribute Actions
    public static final String ACT_ATTR_VIEW = EntityAttributePolicyAction.VIEW.getId();
    public static final String ACT_ATTR_MODIFY = EntityAttributePolicyAction.MODIFY.getId();

    // Resource Types
    public static final String RESOURCE_TYPE_ENTITY = "entity";
    public static final String RESOURCE_TYPE_ENTITY_ATTRIBUTE = "entity_attribute";
    public static final String RESOURCE_TYPE_SCREEN = "screen";
    public static final String RESOURCE_TYPE_MENU = "menu";

    // Special Resources
    public static final String WILDCARD_RESOURCE = "*";
    public static final String WILDCARD_DISPLAY = "All entities (*)";

    // Effects
    public static final String EFFECT_ALLOW = "ALLOW";
    public static final String EFFECT_DENY = "DENY";

    // Types
    public static final String TYPE_SCREEN = "screen";
    public static final String TYPE_MENU = "menu";

    // Meta suffixes
    public static final String META_VIEW = "(View)";
    public static final String META_FRAGMENT = "(Fragment)";
    public static final String META_ALLOW_IN_MENU = "Allow in menu";

    // Action names
    public static final String ACTION_ACCESS = "Access";
    public static final String ACTION_MENU = "menu";

    // Node naming
    public static final String NODE_VIEW_PREFIX = "View: ";
    public static final String NODE_MENU_SUFFIX = " (menu)";

    // Defaults
    public static final int DEFAULT_BATCH_SIZE = 100;
    public static final long DEFAULT_CACHE_TIMEOUT_MS = 300000; // 5 minutes
}
