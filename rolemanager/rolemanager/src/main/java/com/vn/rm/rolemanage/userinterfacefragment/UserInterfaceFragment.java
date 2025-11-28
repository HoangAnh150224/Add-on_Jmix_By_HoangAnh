package com.vn.rm.rolemanage.userinterfacefragment;

import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.grid.ColumnTextAlign;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.data.renderer.ComponentRenderer;
import com.vn.rm.rolemanage.service.RoleManagerService;
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
                .anyMatch(p -> "*".equals(p.getResource())
                        && ResourcePolicyEffect.ALLOW.equals(p.getEffect()));

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

            if (!ResourcePolicyEffect.ALLOW.equalsIgnoreCase(p.getEffect()))
                continue;

            if ("*".equals(p.getResource())) {
                suppressAllowAllEvent = true;
                allowAllViews.setValue(true);
                suppressAllowAllEvent = false;

                applyAllowAll(true);
                continue;
            }

            String key = roleManagerService.buildLeafKey(p.getResource(), "access");
            List<PolicyGroupNode> nodes = roleManagerService.getNodesByKey(key);

            if (nodes != null) {
                for (PolicyGroupNode n : nodes) {
                    n.setAnnotated(true);
                    roleManagerService.applyState(n, true);
                    n.setDenyDefault(false);
                }
            }
        }
    }

    // ===============================================
    // APPLY DB POLICIES
    // ===============================================
    private void applyDbPolicies(ResourceRoleModel model) {

        for (ResourcePolicyModel p : model.getResourcePolicies()) {

            String key = roleManagerService.buildLeafKey(p.getResource(), p.getAction());
            List<PolicyGroupNode> nodes = roleManagerService.getNodesByKey(key);

            if (nodes == null) continue;

            if (ResourcePolicyEffect.ALLOW.equals(p.getEffect())) {
                for (PolicyGroupNode n : nodes) {
                    roleManagerService.applyState(n, true);
                    n.setDenyDefault(false);
                }
            }

            if (ResourcePolicyEffect.DENY.equals(p.getEffect())) {
                for (PolicyGroupNode n : nodes) {
                    roleManagerService.applyState(n, false);
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

        // ============================
        // ALLOW COLUMN
        // ============================
// ============================
// ALLOW COLUMN
// ============================
        policyTreeGrid.addColumn(new ComponentRenderer<>(Checkbox::new, (cb, node) -> {
            cb.setVisible(node.isLeaf());
            cb.setValue("ALLOW".equals(node.getEffect()));

            boolean locked = roleManagerService.isViewLockedByMenu(node);

            if (locked) {
                cb.setEnabled(false);       // 🔒 khóa khi MENU = ALLOW
            } else {
                cb.setEnabled(editable);    // mở bình thường
            }

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient() || locked) return;

                roleManagerService.syncLinkedLeaves(node, e.getValue());
                policyTreeGrid.getDataProvider().refreshAll();
            });


        })).setHeader("Allow");

// ============================
// DENY COLUMN
// ============================
        policyTreeGrid.addColumn(new ComponentRenderer<>(Checkbox::new, (cb, node) -> {

            cb.setVisible(node.isLeaf());
            cb.setValue(!"ALLOW".equals(node.getEffect()));

            boolean locked = roleManagerService.isViewLockedByMenu(node);

            if (locked) {
                cb.setEnabled(false);       // 🔒 khóa deny khi screen bị ép allow
            } else {
                cb.setEnabled(editable);
            }

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient() || locked) return;

                boolean deny = e.getValue();
                boolean allow = !deny;

                roleManagerService.syncLinkedLeaves(node, allow);
                policyTreeGrid.getDataProvider().refreshAll();
            });


        })).setHeader("Deny");

    }


    // ===============================================
    // COLLECT POLICIES
    // ===============================================
    public List<ResourcePolicyModel> collectPoliciesFromTree() {

        List<ResourcePolicyModel> result = new ArrayList<>();

        if (isAllowAllViewsChecked()) {
            result.add(roleManagerService.createPolicy("screen", "*", "access"));
            result.add(roleManagerService.createPolicy("menu", "*", "access"));
            return result;
        }

        for (PolicyGroupNode root : policyTreeDc.getItems())
            roleManagerService.collect(root, result);

        return result;
    }
}
