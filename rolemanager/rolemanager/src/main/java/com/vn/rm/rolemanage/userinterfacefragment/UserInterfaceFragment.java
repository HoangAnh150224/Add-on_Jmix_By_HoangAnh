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

    @Autowired
    private RoleManagerService roleManagerService;
    @Autowired
    private Metadata metadata;

    private boolean suppressAllowAllEvent = false;
    @Autowired
    private RoleModelConverter roleModelConverter;

    public void initUi(ResourceRoleModel model) {

        boolean isAnnotated = model.getSource() == RoleSourceType.ANNOTATED_CLASS;

        ResourceRoleModel annotatedModel = null;

        if (isAnnotated) {
            // ✅ Lấy runtime role thực từ Jmix (đã có normalization)
            ResourceRole runtimeRole = roleManagerService.getRoleByCode(model.getCode());

            // ✅ Convert chính thức, giữ metadata đầy đủ (type, resource, action,...)
            annotatedModel = roleModelConverter.createResourceRoleModel(runtimeRole);

            // ✅ Lưu lại annotated role để isAnnotatedView() hoạt động đúng
            roleManagerService.setAnnotatedRole(annotatedModel);
        } else {
            roleManagerService.setAnnotatedRole(null);
        }

        // Annotated thì disable checkbox Allow All Views
        allowAllViews.setEnabled(!isAnnotated);

        // ✅ Xây lại cây View/Menu Access
        buildTree(model);
        setupTreeGrid(model.getSource().name());

        // ✅ Sau khi cây đã được index, apply annotated role (menu + view)
        if (isAnnotated && annotatedModel != null) {
            applyAnnotated(annotatedModel);
        }

        // ===============================================
        // ALLOW ALL CHECKBOX
        // ===============================================
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
        if (hasAllowAll) {
            applyAllowAll(true);    // 🔥 ép tất cả leaf hiển thị Allow
        }
        allowAllViews.addValueChangeListener(e -> {
            if (!e.isFromClient() || suppressAllowAllEvent)
                return;
            applyAllowAll(Boolean.TRUE.equals(e.getValue()));
        });
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

        if (model.getSource() == RoleSourceType.ANNOTATED_CLASS) {
            applyAnnotated(model);      // chỉ chạy annotated
        } else {
            applyDbPolicies(model);     // chỉ chạy DB
        }


        policyTreeDc.setItems(Arrays.asList(viewRoot, menuRoot));
        policyTreeGrid.setItems(Arrays.asList(viewRoot, menuRoot), PolicyGroupNode::getChildren);
    }

    private void applyDbPolicies(ResourceRoleModel model) {

        // Không làm gì nếu model null hoặc không có policy
        if (model == null || model.getResourcePolicies() == null)
            return;

        for (ResourcePolicyModel p : model.getResourcePolicies()) {

            // chỉ xử lý policy ALLOW
            if (!ResourcePolicyEffect.ALLOW.equalsIgnoreCase(p.getEffect()))
                continue;

            // Nếu là wildcard (*), chỉ hiển thị "Allow All" trên UI
            if ("*".equals(p.getResource())) {
                suppressAllowAllEvent = true;
                allowAllViews.setValue(true);
                suppressAllowAllEvent = false;
                // ❌ Không gọi applyAllowAll(true) — tránh ép toàn bộ node Allow
                continue;
            }

            // Xây key theo đúng type
            String key = roleManagerService.buildLeafKey(
                    p.getResource(),
                    p.getAction() == null ? "Access" : p.getAction(),
                    p.getType()
            );

            List<PolicyGroupNode> nodes = roleManagerService.getNodesByKey(key);
            if (nodes == null || nodes.isEmpty())
                continue;

            for (PolicyGroupNode n : nodes) {
                // Chỉ apply đúng type (menu ↔ menu, screen ↔ screen)
                if (!p.getType().equalsIgnoreCase(n.getType()))
                    continue;

                // ⚠️ Không động vào annotated node (tức annotated = true)
                if (Boolean.TRUE.equals(n.getAnnotated()))
                    continue;

                // ✅ Apply state cho node DB
                roleManagerService.applyState(n, true);
                n.setDenyDefault(false);
            }
        }

        // ✅ Refresh UI để update checkbox
        policyTreeGrid.getDataProvider().refreshAll();
    }




    private void applyAnnotated(ResourceRoleModel model)  {
        if (model == null || model.getResourcePolicies() == null)
            return;

        for (ResourcePolicyModel p : model.getResourcePolicies()) {

            // chỉ quan tâm screen + menu
            if (!("screen".equalsIgnoreCase(p.getType()) || "menu".equalsIgnoreCase(p.getType())))
                continue;

            String key = roleManagerService.buildLeafKey(
                    p.getResource(),
                    p.getAction() == null ? "Access" : p.getAction(),
                    p.getType()
            );

            List<PolicyGroupNode> nodes = roleManagerService.getNodesByKey(key);
            if (nodes == null) continue;

            for (PolicyGroupNode n : nodes) {
                n.setAnnotated(true);

                if (ResourcePolicyEffect.ALLOW.equals(p.getEffect())) {
                    n.setEffect("ALLOW");
                    n.setAllow(true);
                    n.setDeny(false);
                } else {
                    n.setEffect(null);
                    n.setAllow(false);
                    n.setDeny(false);
                }

                roleManagerService.syncLinkedLeaves(n, "ALLOW".equals(n.getEffect()));

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
                boolean checked = Boolean.TRUE.equals(e.getValue());

                if (checked) {
                    // ✔ Tick Deny → xoá allow
                    node.setEffect(null);    // xoá khỏi DB
                    node.setAllow(false);
                    node.setDeny(true);

                    // ✔ bỏ tick Allow All nếu đang bật
                    suppressAllowAllEvent = true;
                    allowAllViews.setValue(false);
                    suppressAllowAllEvent = false;

                } else {
                    // ❗ Bỏ deny → luôn bật Allow
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
            if (!unique.add(key)) {
                return; // tránh trùng lặp
            }

            // ✅ Chuẩn hoá action cho screen/menu

            // ✅ Dùng metadata để tạo model
            ResourcePolicyModel p = metadata.create(ResourcePolicyModel.class);
            p.setId(UUID.randomUUID());
            p.setType(node.getType());
            p.setResource(node.getResource());
            p.setAction(node.getAction());
            p.setEffect(ResourcePolicyEffect.ALLOW);

            // ✅ Gán Policy Group hợp lệ (giúp UI Resource Role Editor hiển thị đúng)
            String group = node.getResource();
            if (group != null && group.endsWith("*")) {
                group = null;
            }
            p.setPolicyGroup(group);

            out.add(p);
        }

        // Duyệt đệ quy con
        for (PolicyGroupNode c : node.getChildren()) {
            collectUnique(c, out, unique);
        }
    }


}
