package com.vn.rm.rolemanage.userinterfacefragment;

import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.grid.ColumnTextAlign;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.data.renderer.ComponentRenderer;
import com.vn.rm.rolemanage.service.RoleManagerService;
import io.jmix.core.Metadata;
import io.jmix.flowui.component.grid.TreeDataGrid;
import io.jmix.flowui.fragment.Fragment;
import io.jmix.flowui.fragment.FragmentDescriptor;
import io.jmix.flowui.model.CollectionContainer;
import io.jmix.flowui.menu.MenuItem;
import io.jmix.flowui.view.ViewComponent;
import io.jmix.security.model.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

@FragmentDescriptor("user-interface-fragment.xml")
public class UserInterfaceFragment extends Fragment<VerticalLayout> {

    @ViewComponent private CollectionContainer<PolicyGroupNode> policyTreeDc;
    @ViewComponent private TreeDataGrid<PolicyGroupNode> policyTreeGrid;
    @ViewComponent private Checkbox allowAllViews;

    @Autowired private RoleManagerService roleManagerService;
    @Autowired
    private Metadata metadata;

    private boolean suppressAllowAllEvent = false;

    // ===============================================
    // INIT UI
    // ===============================================
    public void initUi(ResourceRoleModel model) {

        boolean isAnnotated = model.getSource() == RoleSourceType.ANNOTATED_CLASS;

        if (isAnnotated) {
            ResourceRole runtimeRole = roleManagerService.getRoleByCode(model.getCode());
            ResourceRoleModel annotatedModel =
                    roleManagerService.convertAnnotatedToModel(runtimeRole);
            roleManagerService.setAnnotatedRole(annotatedModel);
        } else {
            roleManagerService.setAnnotatedRole(null);
        }

        allowAllViews.setEnabled(!isAnnotated);

        buildTree(model);
        setupTreeGrid(model.getSource().name());

        boolean hasAllowAll = model.getResourcePolicies().stream()
                .anyMatch(p ->
                        "*".equals(p.getResource())
                                && ResourcePolicyEffect.ALLOW.equals(p.getEffect())
                                && (
                                "screen".equalsIgnoreCase(p.getType()) ||
                                        "menu".equalsIgnoreCase(p.getType())
                        )
                );


        suppressAllowAllEvent = true;
        allowAllViews.setValue(hasAllowAll);
        suppressAllowAllEvent = false;

        allowAllViews.addValueChangeListener(e -> {
            if (!e.isFromClient() || suppressAllowAllEvent) return;
            applyAllowAll(Boolean.TRUE.equals(e.getValue()));
        });
    }

    private boolean isAllowAllViewsChecked() {
        return Boolean.TRUE.equals(allowAllViews.getValue());
    }

    // ===============================================
    // ALLOW ALL
    // ===============================================
    private void applyAllowAll(boolean enable) {
        for (PolicyGroupNode leaf : roleManagerService.getAllIndexedLeaves()) {
            if (enable) {
                leaf.setEffect("ALLOW");
                leaf.setAllow(true);
                leaf.setDeny(false);
            } else {
                leaf.setEffect(null);
                leaf.setAllow(false);
                leaf.setDeny(true);
            }
        }

        policyTreeGrid.getDataProvider().refreshAll();
    }

    // ===============================================
    // BUILD TREE
    // ===============================================
    private void buildTree(ResourceRoleModel model) {

        Map<String, List<MenuItem>> vmMap = roleManagerService.buildViewMenuMap();

        PolicyGroupNode viewRoot = new PolicyGroupNode("View Access", true);
        PolicyGroupNode menuRoot = new PolicyGroupNode("Menu Access", true);

        roleManagerService.buildViewsTree(viewRoot, vmMap);
        viewRoot = roleManagerService.compress(viewRoot);

        roleManagerService.buildMenuTree(menuRoot);

        roleManagerService.clearIndex();
        roleManagerService.indexLeaves(viewRoot);
        roleManagerService.indexLeaves(menuRoot);

        for (PolicyGroupNode leaf : roleManagerService.getAllIndexedLeaves())
            leaf.resetState();

        applyAnnotated(model);
        applyDbPolicies(model);

        policyTreeDc.setItems(Arrays.asList(viewRoot, menuRoot));
        policyTreeGrid.setItems(Arrays.asList(viewRoot, menuRoot), PolicyGroupNode::getChildren);
    }

    // ===============================================
    // APPLY ANNOTATED
    // ===============================================
    private void applyAnnotated(ResourceRoleModel model) {

        for (ResourcePolicyModel p : model.getResourcePolicies()) {

            if (!ResourcePolicyEffect.ALLOW.equals(p.getEffect()))
                continue;

            // allow all
            if ("*".equals(p.getResource())) {
                suppressAllowAllEvent = true;
                allowAllViews.setValue(true);
                suppressAllowAllEvent = false;
                applyAllowAll(true);
                continue;
            }

            // action phải đúng, KHÔNG cứng "access"
            String key = roleManagerService.buildLeafKey(p.getResource(), p.getAction());
            List<PolicyGroupNode> nodes = roleManagerService.getNodesByKey(key);

            if (nodes == null) continue;

            for (PolicyGroupNode n : nodes) {

                // annotated = cannot change
                n.setAnnotated(true);

                // annotated allow
                n.setEffect("ALLOW");
                n.setAllow(true);
                n.setDeny(false);
            }
        }
    }

    private void applyDbPolicies(ResourceRoleModel model) {

        for (ResourcePolicyModel p : model.getResourcePolicies()) {

            String key = roleManagerService.buildLeafKey(p.getResource(), p.getAction());
            List<PolicyGroupNode> nodes = roleManagerService.getNodesByKey(key);
            if (nodes == null) continue;

            for (PolicyGroupNode n : nodes) {

                // annotated ALWAYS wins
                if (Boolean.TRUE.equals(n.getAnnotated()))
                    continue;

                if (ResourcePolicyEffect.ALLOW.equals(p.getEffect())) {
                    n.setEffect("ALLOW");
                    n.setAllow(true);
                    n.setDeny(false);
                }

                if (ResourcePolicyEffect.DENY.equals(p.getEffect())) {
                    n.setEffect(null);
                    n.setAllow(false);
                    n.setDeny(true);
                }
            }
        }
    }


    // ===============================================
    // TREE GRID
    // ===============================================
    private void setupTreeGrid(String source) {
        boolean editable = "DATABASE".equalsIgnoreCase(source);

        policyTreeGrid.removeAllColumns();

        policyTreeGrid.addHierarchyColumn(n -> n.getName())
                .setHeader("Resource")
                .setFlexGrow(4);

        policyTreeGrid.addColumn(PolicyGroupNode::getType)
                .setHeader("Type")
                .setTextAlign(ColumnTextAlign.CENTER);

        policyTreeGrid.addColumn(PolicyGroupNode::getAction)
                .setHeader("Action")
                .setTextAlign(ColumnTextAlign.CENTER);

        policyTreeGrid.addColumn(new ComponentRenderer<>(Checkbox::new, (cb, node) -> {

            cb.setVisible(node.isLeaf());
            cb.setValue(node.isAllow());            // ✔ đúng logic

            boolean locked = roleManagerService.isViewLockedByMenu(node);
            cb.setEnabled(editable && !locked);

            // ✔ luôn sync UI khi node refresh
            cb.addAttachListener(ev -> cb.setValue(node.isAllow()));

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient() || locked) return;

                boolean allow = e.getValue();

                node.setAllow(allow);
                node.setDeny(!allow);
                node.setEffect(allow ? "ALLOW" : null);

                roleManagerService.syncLinkedLeaves(node, allow);

                policyTreeGrid.getDataProvider().refreshItem(node, true);
                if (node.getParent() != null)
                    policyTreeGrid.getDataProvider().refreshItem(node.getParent(), true);
            });

        })).setHeader("Allow");
        policyTreeGrid.addColumn(new ComponentRenderer<>(Checkbox::new, (cb, node) -> {

            cb.setVisible(node.isLeaf());
            cb.setValue(node.isDeny());              // ✔ đúng logic

            boolean locked = roleManagerService.isViewLockedByMenu(node);
            cb.setEnabled(editable && !locked);

            cb.addAttachListener(ev -> cb.setValue(node.isDeny()));

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient() || locked) return;

                boolean deny = e.getValue();
                boolean allow = !deny;

                node.setDeny(deny);
                node.setAllow(allow);
                node.setEffect(allow ? "ALLOW" : null);

                // Nếu tick Deny → tắt Allow All
                if (deny) {
                    suppressAllowAllEvent = true;
                    allowAllViews.setValue(false);
                    suppressAllowAllEvent = false;
                }

                roleManagerService.syncLinkedLeaves(node, allow);

                policyTreeGrid.getDataProvider().refreshItem(node, true);
                if (node.getParent() != null)
                    policyTreeGrid.getDataProvider().refreshItem(node.getParent(), true);
            });

        })).setHeader("Deny");


    }


    // ===============================================
    // COLLECT POLICIES
    // ===============================================
    public List<ResourcePolicyModel> collectPoliciesFromTree() {

        List<ResourcePolicyModel> result = new ArrayList<>();

        // allowAll thì return ngay
        if (Boolean.TRUE.equals(allowAllViews.getValue())) {
            result.add(roleManagerService.createPolicy("screen", "*", "access"));
            result.add(roleManagerService.createPolicy("menu", "*", "access"));
            return result;
        }

        // chỗ này FIX duplicate
        Set<String> unique = new HashSet<>();

        for (PolicyGroupNode root : policyTreeDc.getItems()) {

            collectUnique(root, result, unique);
        }

        return result;
    }
    private void collectUnique(PolicyGroupNode node,
                               List<ResourcePolicyModel> out,
                               Set<String> unique) {

        if (node.isLeaf() && "ALLOW".equals(node.getEffect())) {

            String key = node.getType() + "|" + node.getResource() + "|" + node.getAction();

            if (!unique.contains(key)) {

                unique.add(key);

                // MUST USE metadata.create → Model needs internal meta config
                ResourcePolicyModel p = metadata.create(ResourcePolicyModel.class);
                p.setId(UUID.randomUUID());              // 👈 FIX: REQUIRED
                p.setType(node.getType());
                p.setResource(node.getResource());
                p.setAction(node.getAction());
                p.setEffect("ALLOW");

                out.add(p);
            }
        }

        for (PolicyGroupNode c : node.getChildren()) {
            collectUnique(c, out, unique);
        }
    }

}
