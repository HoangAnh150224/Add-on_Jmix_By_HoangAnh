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

                if (!ResourcePolicyEffect.ALLOW.equalsIgnoreCase(p.getEffect()))
                    continue;

                if ("*".equals(p.getResource())) {
                    suppressAllowAllEvent = true;
                    allowAllViews.setValue(true);
                    suppressAllowAllEvent = false;
                    applyAllowAll(true);
                    continue;
                }

                // Annotated CHỈ apply vào screen
                String key = roleManagerService.buildLeafKey(
                        p.getResource(),
                        "Access",
                        "screen"
                );

                List<PolicyGroupNode> nodes = roleManagerService.getNodesByKey(key);
                if (nodes == null) continue;

                for (PolicyGroupNode n : nodes) {
                    if (!"screen".equalsIgnoreCase(n.getType()))
                        continue; // tuyệt đối không apply vào menu

                    n.setAnnotated(true);
                    roleManagerService.applyState(n, true);
                    n.setDenyDefault(false);
                }
            }
        }


        // ===============================================
        // APPLY DB POLICIES
        // ===============================================
        private void applyDbPolicies(ResourceRoleModel model) {

            for (ResourcePolicyModel p : model.getResourcePolicies()) {

                // DB chỉ apply vào SCREEN
                if (!"screen".equalsIgnoreCase(p.getType()))
                    continue;

                String key = roleManagerService.buildLeafKey(
                        p.getResource(),
                        p.getAction(),
                        "screen"
                );

                List<PolicyGroupNode> nodes = roleManagerService.getNodesByKey(key);
                if (nodes == null) continue;

                for (PolicyGroupNode n : nodes) {
                    if (!"screen".equalsIgnoreCase(n.getType()))
                        continue; // Không apply vào MENU

                    if (ResourcePolicyEffect.ALLOW.equals(p.getEffect())) {
                        roleManagerService.applyState(n, true);
                        n.setDenyDefault(false);
                    }

                    if (ResourcePolicyEffect.DENY.equals(p.getEffect())) {
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
        policyTreeGrid.addColumn(new ComponentRenderer<>(() -> {
            Checkbox cb = new Checkbox();
            cb.addClassName("allow-checkbox");
            return cb;
        }, (cb, node) -> {

            cb.setVisible(node.isLeaf());
            cb.setValue("ALLOW".equals(node.getEffect()));

            boolean locked = roleManagerService.isViewLockedByMenu(node);

            if (locked) {
                cb.setEnabled(false);  // 🔒 khóa VIEW khi MENU = ALLOW
            } else {
                cb.setEnabled(editable);
            }

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient()) return;

                // ✅ Không cho phép thay đổi nếu bị lock
                if (locked) {
                    cb.setValue("ALLOW".equals(node.getEffect()));
                    return;
                }

                roleManagerService.syncLinkedLeaves(node, e.getValue());

                // 🔁 Force Vaadin re-render toàn bộ grid (renderer được gọi lại)
                policyTreeGrid.getDataProvider().refreshAll();
            });
        })).setHeader("Allow");


// ============================
// DENY COLUMN
// ============================
        policyTreeGrid.addColumn(new ComponentRenderer<>(() -> {
            Checkbox cb = new Checkbox();
            cb.addClassName("deny-checkbox");
            return cb;
        }, (cb, node) -> {

            cb.setVisible(node.isLeaf());
            cb.setValue(!"ALLOW".equals(node.getEffect()));

            boolean locked = roleManagerService.isViewLockedByMenu(node);

            if (locked) {
                cb.setEnabled(false); // 🔒 không cho deny nếu bị ép allow
            } else {
                cb.setEnabled(editable);
            }

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient()) return;

                if (locked) {
                    cb.setValue(!"ALLOW".equals(node.getEffect()));
                    return;
                }

                boolean deny = e.getValue();
                boolean allow = !deny;

                if (deny) {
                    node.setEffect(null);
                    node.setAllow(false);
                    node.setDeny(true);

                    suppressAllowAllEvent = true;
                    allowAllViews.setValue(false);
                    suppressAllowAllEvent = false;
                } else {
                    node.setEffect("ALLOW");
                    node.setAllow(true);
                    node.setDeny(false);
                }

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

        // allowAll thì return ngay
        if (Boolean.TRUE.equals(allowAllViews.getValue())) {
            result.add(roleManagerService.createPolicy("screen", "*", "Access"));
            result.add(roleManagerService.createPolicy("menu", "*", "Access"));
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
