package com.vn.rm.rolemanage.specificfragment;

import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.data.renderer.ComponentRenderer;
import com.vn.rm.rolemanage.service.RoleManagerService;
import io.jmix.core.security.SpecificPolicyInfoRegistry;
import io.jmix.core.security.SpecificPolicyInfoRegistry.SpecificPolicyInfo;
import io.jmix.flowui.component.grid.TreeDataGrid;
import io.jmix.flowui.fragment.Fragment;
import io.jmix.flowui.fragment.FragmentDescriptor;
import io.jmix.flowui.model.CollectionContainer;
import io.jmix.flowui.view.Subscribe;
import io.jmix.flowui.view.Target;
import io.jmix.flowui.view.ViewComponent;
import io.jmix.security.model.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

@FragmentDescriptor("specific-fragment.xml")
public class SpecificFragment extends Fragment<VerticalLayout> {

    @Autowired
    private SpecificPolicyInfoRegistry registry;

    @Autowired
    private RoleManagerService roleManagerService;

    @ViewComponent
    private TreeDataGrid<SpecificNode> specificTree;

    @ViewComponent
    private CollectionContainer<SpecificNode> specificDc;

    @ViewComponent
    private Checkbox allowAllSpecific;

    private boolean suppressAllowAll = false;


    // ======================================================================
    // INIT — MAIN ENTRY
    // ======================================================================
    public void initSpecific(ResourceRoleModel roleModel) {

        // Annotated role để check các specific được cho phép bởi @SpecificPolicy
        ResourceRoleModel annotatedModel = null;

        if (roleModel.getSource() == RoleSourceType.ANNOTATED_CLASS) {
            ResourceRole runtimeRole = roleManagerService.getRoleByCode(roleModel.getCode());
            annotatedModel = roleManagerService.convertAnnotatedToModel(runtimeRole);
        }

        List<SpecificNode> roots = buildTree(roleModel, annotatedModel);

        specificDc.setItems(roots);
        specificTree.setItems(roots, SpecificNode::getChildren);

        boolean editable = (roleModel.getSource() == RoleSourceType.DATABASE);
        setupGrid(editable);

        // ---- INIT AllowAll ----
        boolean hasAllowAll = roleModel.getResourcePolicies().stream()
                .anyMatch(p -> "specific".equalsIgnoreCase(p.getType())
                        && "*".equals(p.getResource())
                        && ResourcePolicyEffect.ALLOW.equals(p.getEffect()));

        suppressAllowAll = true;
        allowAllSpecific.setValue(hasAllowAll);
        suppressAllowAll = false;

        allowAllSpecific.setEnabled(editable);

        allowAllSpecific.addValueChangeListener(e -> {
            if (!e.isFromClient() || suppressAllowAll)
                return;

            applyAllowAll(Boolean.TRUE.equals(e.getValue()));
        });
    }


    // ======================================================================
    // ALLOW ALL
    // ======================================================================
    private void applyAllowAll(boolean enable) {

        for (SpecificNode group : specificDc.getItems()) {
            for (SpecificNode leaf : group.getChildren()) {

                if (Boolean.TRUE.equals(leaf.getAnnotated()))
                    continue; // annotated = lock

                if (enable) {
                    leaf.setEffect("ALLOW");
                    leaf.setAllow(true);
                    leaf.setDeny(false);
                } else {
                    leaf.setEffect(null);     // null = DENY
                    leaf.setAllow(false);
                    leaf.setDeny(true);
                }
            }
        }
        specificTree.getDataProvider().refreshAll();
    }


    // ======================================================================
    // BUILD TREE (ANNOTATED + DB)
    // ======================================================================
    private List<SpecificNode> buildTree(ResourceRoleModel model, ResourceRoleModel annotatedModel) {

        // Annotated map (từ code)
        Set<String> annotatedAllowed = new HashSet<>();
        if (annotatedModel != null && annotatedModel.getResourcePolicies() != null) {
            for (ResourcePolicyModel p : annotatedModel.getResourcePolicies()) {
                if ("specific".equalsIgnoreCase(p.getType())
                        && ResourcePolicyEffect.ALLOW.equals(p.getEffect())) {
                    annotatedAllowed.add(p.getResource());
                }
            }
        }

        Map<String, SpecificNode> groups = new TreeMap<>();

        for (SpecificPolicyInfo info : registry.getSpecificPolicyInfos()) {

            String id = info.getName();
            String group = extractGroup(id);

            groups.computeIfAbsent(group, g -> new SpecificNode(g, true));
            SpecificNode groupNode = groups.get(group);

            SpecificNode leaf = new SpecificNode(id, false);
            leaf.setParent(groupNode);
            groupNode.getChildren().add(leaf);

            // ============================================
            // 1) Annotated (code) → ALWAYS ALLOW
            // ============================================
            if (annotatedAllowed.contains(id)) {
                leaf.setAnnotated(true);
                leaf.setEffect("ALLOW");
                leaf.setAllow(true);
                leaf.setDeny(false);
            }

            // ============================================
            // 2) DB override
            // ============================================
            applyDbOverride(leaf, model);
        }

        return new ArrayList<>(groups.values());
    }


    // ======================================================================
    // APPLY DB OVERRIDE
    // ======================================================================
    private void applyDbOverride(SpecificNode leaf, ResourceRoleModel model) {

        if (model.getResourcePolicies() == null)
            return;

        for (ResourcePolicyModel p : model.getResourcePolicies()) {

            if (!"specific".equalsIgnoreCase(p.getType()))
                continue;

            if (!"execute".equalsIgnoreCase(p.getAction()))
                continue;

            if (!leaf.getName().equals(p.getResource()))
                continue;

            if (ResourcePolicyEffect.ALLOW.equals(p.getEffect())) {
                // DB allow
                leaf.setEffect("ALLOW");
                leaf.setAllow(true);
                leaf.setDeny(false);
            } else {
                // DB deny
                leaf.setEffect(null);
                leaf.setAllow(false);
                leaf.setDeny(true);
            }
        }
    }



    // ======================================================================
    // GRID RENDER
    // ======================================================================
    private void setupGrid(boolean editable) {

        specificTree.removeAllColumns();

        specificTree.addHierarchyColumn(SpecificNode::getName)
                .setHeader("Permission");

        // ALLOW
        specificTree.addColumn(new ComponentRenderer<>(Checkbox::new, (cb, node) -> {

            boolean locked = Boolean.TRUE.equals(node.getAnnotated());
            cb.setVisible(node.isLeaf());
            cb.setEnabled(editable && !locked);

            cb.setValue("ALLOW".equals(node.getEffect()));

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient()) return;

                boolean checked = Boolean.TRUE.equals(e.getValue());

                if (checked) {
                    node.setEffect("ALLOW");
                    node.setAllow(true);
                    node.setDeny(false);
                } else {
                    // ❌ Bỏ tick Allow → phải tắt AllowAll
                    suppressAllowAll = true;
                    allowAllSpecific.setValue(false);
                    suppressAllowAll = false;

                    node.setEffect(null);
                    node.setAllow(false);
                    node.setDeny(true);
                }

                specificTree.getDataProvider().refreshAll();
            });


        })).setHeader("Allow");

        // DENY
        specificTree.addColumn(new ComponentRenderer<>(Checkbox::new, (cb, node) -> {

            boolean locked = Boolean.TRUE.equals(node.getAnnotated());
            cb.setVisible(node.isLeaf());
            cb.setEnabled(editable && !locked);

            cb.setValue(!"ALLOW".equals(node.getEffect()));

            cb.addValueChangeListener(e -> {
                if (!e.isFromClient()) return;

                boolean checked = Boolean.TRUE.equals(e.getValue());

                if (checked) {

                    suppressAllowAll = true;
                    allowAllSpecific.setValue(false);
                    suppressAllowAll = false;

                    node.setEffect(null);
                    node.setAllow(false);
                    node.setDeny(true);
                }
                else {
                    node.setEffect("ALLOW");
                    node.setAllow(true);
                    node.setDeny(false);
                }

                specificTree.getDataProvider().refreshAll();
            });

        })).setHeader("Deny");
    }


    // ======================================================================
    // GROUP EXTRACT
    // ======================================================================
    private String extractGroup(String id) {
        String[] p = id.split("\\.");
        if (p.length >= 2) return p[0] + "." + p[1];
        return p[0];
    }


    // ======================================================================
    // COLLECT POLICIES
    // ======================================================================
    public List<ResourcePolicyModel> collectSpecificPolicies() {

        List<ResourcePolicyModel> out = new ArrayList<>();

        if (Boolean.TRUE.equals(allowAllSpecific.getValue())) {
            out.add(roleManagerService.createPolicy("specific", "*", "execute"));
            return out;
        }

        for (SpecificNode group : specificDc.getItems()) {
            for (SpecificNode leaf : group.getChildren()) {

                if (!"ALLOW".equals(leaf.getEffect()))
                    continue;

                out.add(roleManagerService.createPolicy(
                        "specific",
                        leaf.getName(),
                        "execute"
                ));
            }
        }
        return out;
    }


}
