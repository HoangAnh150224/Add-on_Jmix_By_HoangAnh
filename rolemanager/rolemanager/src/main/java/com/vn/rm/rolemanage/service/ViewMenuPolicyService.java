package com.vn.rm.rolemanage.service;

import com.vn.rm.rolemanage.constants.PolicyConstants;
import com.vn.rm.rolemanage.userinterfacefragment.PolicyGroupNode;
import io.jmix.flowui.view.ViewRegistry;
import io.jmix.flowui.fragment.FragmentDescriptor;
import io.jmix.flowui.menu.MenuConfig;
import io.jmix.flowui.menu.MenuItem;
import io.jmix.security.model.ResourcePolicyEffect;
import io.jmix.security.model.ResourcePolicyModel;
import io.jmix.security.model.ResourceRoleModel;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.classreading.CachingMetadataReaderFactory;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.LinkedHashMap;
import java.util.stream.Collectors;

/**
 * Service for view and menu tree operations
 * Handles scanning, tree building, and view-menu mapping
 */
@Component("rm_ViewMenuPolicyService")
public class ViewMenuPolicyService {

    private final ViewRegistry viewRegistry;
    private final MenuConfig menuConfig;
    private final ApplicationContext applicationContext;

    public ViewMenuPolicyService(ViewRegistry viewRegistry,
                                MenuConfig menuConfig,
                                ApplicationContext applicationContext) {
        this.viewRegistry = viewRegistry;
        this.menuConfig = menuConfig;
        this.applicationContext = applicationContext;
    }

    /**
     * Build view menu map: viewId → list of MenuItems containing that view
     */
    @NonNull
    public Map<String, List<MenuItem>> buildViewMenuMap() {
        Map<String, List<MenuItem>> map = new HashMap<>();
        for (MenuItem root : menuConfig.getRootItems()) {
            collectMenuItems(root, map);
        }
        return map;
    }

    /**
     * Scan classpath for fragments with @FragmentDescriptor annotation
     */
    @NonNull
    public Map<String, String> scanFragments() {
        Map<String, String> result = new HashMap<>();
        try {
            String basePackage = getBasePackage();
            if (basePackage == null) {
                return result;
            }

            PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
            String path = "classpath*:" + basePackage.replace('.', '/') + "/**/*.class";

            Resource[] resources = resolver.getResources(path);
            CachingMetadataReaderFactory factory = new CachingMetadataReaderFactory();

            for (Resource resource : resources) {
                MetadataReader reader = factory.getMetadataReader(resource);
                AnnotationMetadata meta = reader.getAnnotationMetadata();

                // fragment but NOT view
                if (meta.hasAnnotation(FragmentDescriptor.class.getName()) &&
                        !meta.hasAnnotation("io.jmix.flowui.view.ViewController")) {

                    String className = reader.getClassMetadata().getClassName();
                    String simpleName = className.substring(className.lastIndexOf('.') + 1);
                    result.put(simpleName, className);
                }
            }
        } catch (Exception e) {
            // Log error but don't fail
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Build complete menu tree from MenuConfig
     */
    public void buildMenuTree(@NonNull PolicyGroupNode menuRoot) {
        for (MenuItem root : menuConfig.getRootItems()) {
            addMenuNode(menuRoot, root);
        }
    }

    /**
     * Build views tree with package hierarchy
     */
    public void buildViewsTree(@NonNull PolicyGroupNode root,
                              @NonNull Map<String, List<MenuItem>> viewMenuMap,
                              @NonNull ResourceRoleModel annotatedRole) {
        Map<String, String> classToViewId = buildClassToViewIdMap();
        Map<String, String> fragments = scanFragments();

        // Process Views
        for (Map.Entry<String, String> entry : classToViewId.entrySet()) {
            String className = entry.getKey();
            String viewId = entry.getValue();

            PolicyGroupNode parent = buildPackageTree(root, className);
            List<MenuItem> menuItems = viewMenuMap.get(viewId);

            if (menuItems != null && !menuItems.isEmpty()) {
                boolean singleMenu = menuItems.size() == 1;
                for (MenuItem menuItem : menuItems) {
                    PolicyGroupNode menuFolder = ensureMenuFolder(parent, menuItem, singleMenu);
                    addViewLeaf(menuFolder, viewId, Collections.singletonList(menuItem), annotatedRole);
                }
                continue;
            }

            addViewLeaf(parent, viewId, Collections.emptyList(), annotatedRole);
        }

        // Process Fragments
        for (String className : fragments.values()) {
            PolicyGroupNode parent = buildPackageTree(root, className);
            String simple = className.substring(className.lastIndexOf('.') + 1);
            addFragmentLeaf(parent, simple, annotatedRole);
        }
    }

    // Private helper methods

    private void collectMenuItems(@NonNull MenuItem item, @NonNull Map<String, List<MenuItem>> map) {
        if (item.getView() != null) {
            map.computeIfAbsent(item.getView(), k -> new ArrayList<>()).add(item);
        }

        for (MenuItem child : item.getChildren()) {
            collectMenuItems(child, map);
        }
    }

    @Nullable
    private String getBasePackage() {
        try {
            return applicationContext.getBeansWithAnnotation(SpringBootApplication.class)
                    .values().iterator().next()
                    .getClass().getPackageName();
        } catch (Exception e) {
            return null;
        }
    }

    @NonNull
    private Map<String, String> buildClassToViewIdMap() {
        Map<String, String> classToViewId = new LinkedHashMap<>();

        viewRegistry.getViewInfos().forEach(info -> {
            if (info.getControllerClass() == null) {
                return;
            }

            String className = info.getControllerClass().getName();
            String viewId = info.getId();

            classToViewId.compute(className, (key, existing) ->
                    selectPreferredViewId(existing, viewId));
        });

        return classToViewId;
    }

    @Nullable
    private String selectPreferredViewId(@Nullable String existing, @Nullable String candidate) {
        if (existing == null) {
            return candidate;
        }

        boolean existingCustom = isCustomViewId(existing);
        boolean candidateCustom = isCustomViewId(candidate);

        if (candidateCustom && !existingCustom) {
            return candidate;
        }

        return existing;
    }

    private boolean isCustomViewId(@Nullable String viewId) {
        if (viewId == null || viewId.isEmpty()) {
            return false;
        }
        return viewId.contains(".") || viewId.contains("_") ||
                Character.isLowerCase(viewId.charAt(0));
    }

    @NonNull
    private PolicyGroupNode buildPackageTree(@NonNull PolicyGroupNode root, @NonNull String className) {
        String[] parts = className.split("\\.");
        PolicyGroupNode current = root;

        for (int i = 0; i < parts.length - 1; i++) {
            String folder = parts[i];

            PolicyGroupNode existing = current.getChildren().stream()
                    .filter(n -> n.getGroup() && folder.equals(n.getName()))
                    .findFirst()
                    .orElse(null);

            if (existing == null) {
                existing = new PolicyGroupNode(folder, true);
                existing.setParent(current);
                current.getChildren().add(existing);
            }
            current = existing;
        }
        return current;
    }

    private void addMenuNode(@NonNull PolicyGroupNode parentNode, @NonNull MenuItem item) {
        String caption = item.getView() != null ? item.getView() : item.getId();

        PolicyGroupNode groupNode = new PolicyGroupNode(caption, true);
        groupNode.setType(PolicyConstants.TYPE_MENU);
        groupNode.setParent(parentNode);
        parentNode.getChildren().add(groupNode);

        boolean hasView = item.getView() != null;
        boolean hasChildren = !item.getChildren().isEmpty();

        // Case 1: Menu item has VIEW → create 2 leaves
        if (hasView) {
            String viewId = item.getView();

            // MENU leaf
            PolicyGroupNode allowMenu = new PolicyGroupNode("Allow in menu", false);
            allowMenu.setType(PolicyConstants.TYPE_MENU);
            allowMenu.setResource(viewId);
            allowMenu.setAction(PolicyConstants.ACTION_ACCESS);
            allowMenu.setParent(groupNode);
            groupNode.getChildren().add(allowMenu);

            // VIEW leaf
            PolicyGroupNode allowView = new PolicyGroupNode(PolicyConstants.NODE_VIEW_PREFIX + viewId, false);
            allowView.setType(PolicyConstants.TYPE_SCREEN);
            allowView.setResource(viewId);
            allowView.setAction(PolicyConstants.ACTION_ACCESS);
            allowView.setParent(groupNode);
            groupNode.getChildren().add(allowView);
        }

        // Case 2: Has children → build recursively
        if (hasChildren) {
            for (MenuItem child : item.getChildren()) {
                addMenuNode(groupNode, child);
            }
            return;
        }

        // Case 3: No view, no children → plain menu leaf
        if (!hasView && !hasChildren) {
            PolicyGroupNode leaf = new PolicyGroupNode(caption, false);
            leaf.setType(PolicyConstants.TYPE_MENU);
            String res = item.getView() != null ? item.getView() : item.getId();
            leaf.setResource(res);
            leaf.setAction(PolicyConstants.ACTION_ACCESS);
            leaf.setParent(groupNode);
            groupNode.getChildren().add(leaf);
        }
    }

    @NonNull
    private PolicyGroupNode ensureMenuFolder(@NonNull PolicyGroupNode parent,
                                            @NonNull MenuItem item,
                                            boolean singleMenuGroup) {
        Deque<MenuItem> stack = new ArrayDeque<>();
        MenuItem current = item;

        while (current != null) {
            stack.push(current);
            current = current.getParent();
        }

        PolicyGroupNode curNode = parent;
        while (!stack.isEmpty()) {
            MenuItem menuItem = stack.pop();
            String caption = menuItem.getId();

            PolicyGroupNode existing = curNode.getChildren().stream()
                    .filter(n -> Boolean.TRUE.equals(n.getGroup()) && caption.equals(n.getName()))
                    .findFirst()
                    .orElse(null);

            if (existing == null) {
                existing = new PolicyGroupNode(caption, true);
                existing.setType(PolicyConstants.TYPE_MENU);
                existing.setParent(curNode);
                curNode.getChildren().add(existing);
            }
            curNode = existing;
        }

        if (!singleMenuGroup) {
            String leafName = item.getId() + PolicyConstants.NODE_MENU_SUFFIX;

            PolicyGroupNode existingLeaf = curNode.getChildren().stream()
                    .filter(n -> !Boolean.TRUE.equals(n.getGroup()) && leafName.equals(n.getName()))
                    .findFirst()
                    .orElse(null);

            if (existingLeaf == null) {
                PolicyGroupNode marker = new PolicyGroupNode(leafName, false);
                marker.setType(PolicyConstants.TYPE_MENU);
                marker.setResource(item.getId());
                marker.setAction(PolicyConstants.ACTION_MENU);
                marker.setParent(curNode);
                curNode.getChildren().add(marker);
                return marker;
            }
        }

        return curNode;
    }

    private void addViewLeaf(@NonNull PolicyGroupNode parent,
                            @NonNull String viewId,
                            @NonNull List<MenuItem> menuItems,
                            @NonNull ResourceRoleModel annotatedRole) {
        boolean isAnnotatedScreen = isAnnotatedView(viewId, annotatedRole);
        boolean isAnnotatedMenu = isAnnotatedMenu(viewId, annotatedRole);

        // Case 1: View in menu → create MENU leaf + VIEW leaf
        if (menuItems != null && !menuItems.isEmpty()) {
            boolean singleMenu = menuItems.size() == 1;

            for (MenuItem menuItem : menuItems) {
                String caption = singleMenu
                        ? PolicyConstants.META_ALLOW_IN_MENU
                        : PolicyConstants.META_ALLOW_IN_MENU + " (" + menuItem.getId() + ")";

                PolicyGroupNode allowMenu = new PolicyGroupNode(caption, false);
                allowMenu.setType(PolicyConstants.TYPE_MENU);
                allowMenu.setResource(viewId);
                allowMenu.setAction(PolicyConstants.ACTION_ACCESS);
                allowMenu.setAnnotated(isAnnotatedMenu);
                allowMenu.setParent(parent);

                parent.getChildren().add(allowMenu);
            }

            // VIEW leaf
            PolicyGroupNode allowView = new PolicyGroupNode(PolicyConstants.NODE_VIEW_PREFIX + viewId, false);
            allowView.setType(PolicyConstants.TYPE_SCREEN);
            allowView.setResource(viewId);
            allowView.setAction(PolicyConstants.ACTION_ACCESS);
            allowView.setMeta(PolicyConstants.META_VIEW);
            allowView.setAnnotated(isAnnotatedScreen);
            allowView.setParent(parent);

            parent.getChildren().add(allowView);
            return;
        }

        // Case 2: View not in menu → only VIEW leaf
        PolicyGroupNode leaf = new PolicyGroupNode(viewId, false);
        leaf.setType(PolicyConstants.TYPE_SCREEN);
        leaf.setResource(viewId);
        leaf.setAction(PolicyConstants.ACTION_ACCESS);
        leaf.setMeta(PolicyConstants.META_VIEW);
        leaf.setAnnotated(isAnnotatedScreen);
        leaf.setParent(parent);

        parent.getChildren().add(leaf);
    }

    private void addFragmentLeaf(@NonNull PolicyGroupNode parent,
                                @NonNull String simpleName,
                                @NonNull ResourceRoleModel annotatedRole) {
        boolean isAnnotated = isAnnotatedFragment(simpleName, annotatedRole);

        PolicyGroupNode leaf = new PolicyGroupNode(simpleName, false);
        leaf.setType(PolicyConstants.TYPE_SCREEN);
        leaf.setResource(simpleName);
        leaf.setAction(PolicyConstants.ACTION_ACCESS);
        leaf.setMeta(PolicyConstants.META_FRAGMENT);
        leaf.setAnnotated(isAnnotated);
        leaf.setParent(parent);

        parent.getChildren().add(leaf);
    }

    private boolean isAnnotatedView(@NonNull String viewId, @NonNull ResourceRoleModel annotatedRole) {
        return annotatedRole.getResourcePolicies().stream()
                .anyMatch(p ->
                        ResourcePolicyEffect.ALLOW.equals(p.getEffect())
                                && PolicyConstants.TYPE_SCREEN.equalsIgnoreCase(p.getType())
                                && (PolicyConstants.WILDCARD_RESOURCE.equals(p.getResource()) ||
                                    p.getResource().equals(viewId))
                );
    }

    private boolean isAnnotatedMenu(@NonNull String viewId, @NonNull ResourceRoleModel annotatedRole) {
        return annotatedRole.getResourcePolicies().stream()
                .anyMatch(p ->
                        ResourcePolicyEffect.ALLOW.equals(p.getEffect())
                                && PolicyConstants.TYPE_MENU.equalsIgnoreCase(p.getType())
                                && (PolicyConstants.WILDCARD_RESOURCE.equals(p.getResource()) ||
                                    p.getResource().equals(viewId))
                );
    }

    private boolean isAnnotatedFragment(@NonNull String simpleName, @NonNull ResourceRoleModel annotatedRole) {
        return annotatedRole.getResourcePolicies().stream()
                .anyMatch(p ->
                        ResourcePolicyEffect.ALLOW.equals(p.getEffect())
                                && PolicyConstants.TYPE_SCREEN.equalsIgnoreCase(p.getType())
                                && (PolicyConstants.WILDCARD_RESOURCE.equals(p.getResource()) ||
                                    p.getResource().equals(simpleName))
                );
    }
}
