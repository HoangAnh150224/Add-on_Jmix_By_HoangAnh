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
import io.jmix.flowui.view.Subscribe;
import io.jmix.flowui.view.Target;
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

        PolicyGroupNode viewRoot = new PolicyGroupNode("Tất cả màn hình", true);
        PolicyGroupNode menuRoot = new PolicyGroupNode("Màn hình chính", true);

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

        if (model == null || model.getResourcePolicies() == null)
            return;

        for (ResourcePolicyModel p : model.getResourcePolicies()) {

            if (!ResourcePolicyEffect.ALLOW.equalsIgnoreCase(p.getEffect()))
                continue;

            if ("*".equals(p.getResource())) {
                suppressAllowAllEvent = true;
                allowAllViews.setValue(true);
                suppressAllowAllEvent = false;
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
                .setHeader("Tài nguyên")
                .setFlexGrow(5);

        policyTreeGrid.addColumn(PolicyGroupNode::getType)
                .setHeader("Thể loại")
                .setFlexGrow(0)
                .setAutoWidth(true)// Không cho phép giãn thêm
                .setTextAlign(ColumnTextAlign.CENTER);

        policyTreeGrid.addColumn(PolicyGroupNode::getAction)
                .setHeader("Hành động")
                .setFlexGrow(0)      // Không cho phép giãn thêm
                .setAutoWidth(true)
                .setTextAlign(ColumnTextAlign.CENTER);

        // ============================
        // ALLOW COLUMN
        // ============================
        policyTreeGrid.addColumn(new ComponentRenderer<>(Checkbox::new, (cb, node) -> {
            cb.setVisible(node.isLeaf());
            cb.setValue("ALLOW".equals(node.getEffect()));

            boolean locked = roleManagerService.isViewLockedByMenu(node);
            cb.setEnabled(!locked && editable);

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient() || locked) return;

                // ĐỒNG BỘ TRẠNG THÁI NGAY TRÊN NODE
                boolean isAllow = Boolean.TRUE.equals(e.getValue());
                if (isAllow) {
                    node.setEffect("ALLOW");
                    node.setAllow(true);
                    node.setDeny(false);
                } else {
                    node.setEffect(null);
                    node.setAllow(false);
                    node.setDeny(true);

                    // Bỏ tick "Allow All" nếu người dùng bỏ tick một quyền bất kỳ
                    suppressAllowAllEvent = true;
                    allowAllViews.setValue(false);
                    suppressAllowAllEvent = false;
                }

                // 1. Cập nhật logic nghiệp vụ (đồng bộ Menu <-> Screen trong database/service)
                roleManagerService.syncLinkedLeaves(node, isAllow);

                // 2. Refresh các node bị ảnh hưởng để cập nhật cả cột ALLOW và DENY
                refreshAffectedNodes(node);
            });
        })).setHeader("Cho phép")
                .setFlexGrow(0)
                .setTextAlign(ColumnTextAlign.CENTER)
                .setWidth("110px")
        ;

        // ============================
        // CỘT KHÓA (DENY)
        // ============================
        policyTreeGrid.addColumn(new ComponentRenderer<>(Checkbox::new, (cb, node) -> {
            cb.setVisible(node.isLeaf());
            cb.setValue(!"ALLOW".equals(node.getEffect()));

            boolean locked = roleManagerService.isViewLockedByMenu(node);
            cb.setEnabled(!locked && editable);

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient() || locked) return;

                // ĐỒNG BỘ TRẠNG THÁI NGAY TRÊN NODE
                boolean isDeny = Boolean.TRUE.equals(e.getValue());
                if (isDeny) {
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

                // 1. Cập nhật logic nghiệp vụ (Nếu Deny = true thì Allow = false)
                roleManagerService.syncLinkedLeaves(node, !isDeny);

                // 2. Refresh các node bị ảnh hưởng
                refreshAffectedNodes(node);
            });
        })).setHeader("Khóa")
                .setTextAlign(ColumnTextAlign.CENTER)
                .setFlexGrow(0)
                .setWidth("100px");

    }
    private void refreshAffectedNodes(PolicyGroupNode currentNode) {
        if (currentNode == null || currentNode.getResource() == null) return;

        String resourceName = currentNode.getResource();

        for (PolicyGroupNode leaf : roleManagerService.getAllIndexedLeaves()) {
            if (resourceName.equals(leaf.getResource())) {

                policyTreeGrid.getDataProvider().refreshItem(leaf);
            }
        }
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

    @Subscribe(id = "resourcePoliciesDc", target = Target.DATA_CONTAINER)
    public void onResourcePoliciesDcCollectionChange(final CollectionContainer.CollectionChangeEvent<ResourcePolicyModel> event) {

    }


}
