package com.vn.rm.rolemanage.specificfragment;

import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.data.renderer.ComponentRenderer;
import com.vn.rm.rolemanage.service.RoleManagerService;
import io.jmix.core.Metadata;
import io.jmix.core.accesscontext.SpecificOperationAccessContext;
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
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.classreading.CachingMetadataReaderFactory;
import org.springframework.core.type.classreading.MetadataReader;

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
    @Autowired
    private Metadata metadata;
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
        if (hasAllowAll) {
            applyAllowAll(true);    // 🔥 ép tất cả leaf hiển thị Allow
        }

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

    private Map<String, String> scanSpecificClasses() {

        Map<String, String> map = new HashMap<>();

        try {
            PathMatchingResourcePatternResolver resolver =
                    new PathMatchingResourcePatternResolver();

            Resource[] resources = resolver.getResources("classpath*:io/jmix/**/*.class");

            CachingMetadataReaderFactory factory = new CachingMetadataReaderFactory();

            for (Resource r : resources) {
                MetadataReader reader = factory.getMetadataReader(r);

                String className = reader.getClassMetadata().getClassName();
                Class<?> cls;

                try {
                    cls = Class.forName(className);
                } catch (Throwable e) {
                    continue;
                }

                if (SpecificOperationAccessContext.class.isAssignableFrom(cls)
                        && !cls.equals(SpecificOperationAccessContext.class)) {

                    // lấy static final NAME
                    try {
                        String policyId = (String) cls.getField("NAME").get(null);
                        map.put(policyId, className);
                    } catch (Exception ignored) {}
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return map;
    }

    // ======================================================================
    // BUILD TREE (ANNOTATED + DB)
    // ======================================================================
    private List<SpecificNode> buildTree(ResourceRoleModel model, ResourceRoleModel annotatedModel) {

        Map<String, String> classMap = scanSpecificClasses();  // <policyId, className>

        Set<String> annotatedAllowed = new HashSet<>();
        if (annotatedModel != null) {
            for (ResourcePolicyModel p : annotatedModel.getResourcePolicies()) {
                if ("specific".equalsIgnoreCase(p.getType())
                        && ResourcePolicyEffect.ALLOW.equals(p.getEffect())) {
                    annotatedAllowed.add(p.getResource());
                }
            }
        }

        Map<String, SpecificNode> groups = new TreeMap<>();

        for (SpecificPolicyInfo info : registry.getSpecificPolicyInfos()) {

            String policyId = info.getName();
            String className = classMap.get(policyId);

            if (className == null)
                continue; // không có class → bỏ

            String groupId = extractGroupFromClass(className);
            String leafId = policyId;

            SpecificNode groupNode = groups.computeIfAbsent(
                    groupId,
                    k -> new SpecificNode(groupId, true)
            );

            SpecificNode leaf = new SpecificNode(leafId, false);
            leaf.setParent(groupNode);
            groupNode.getChildren().add(leaf);

            // annotated
            if (annotatedAllowed.contains(policyId)) {
                leaf.setAnnotated(true);
                leaf.setAllow(true);
                leaf.setDeny(false);
                leaf.setEffect("ALLOW");
            }

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

            if (!"Access".equalsIgnoreCase(p.getAction()))
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
                .setHeader("Quyền hạn");

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
                    suppressAllowAll = true;
                    allowAllSpecific.setValue(false);
                    suppressAllowAll = false;

                    node.setEffect(null);
                    node.setAllow(false);
                    node.setDeny(true);
                }

                specificTree.getDataProvider().refreshAll();
            });


        })).setHeader("Cho Phép");

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

        })).setHeader("Khóa");
    }


    // ======================================================================
    // GROUP EXTRACT
    // ======================================================================
    private String extractGroupFromClass(String className) {
        int idx = className.indexOf(".accesscontext.");
        if (idx > 0) {
            return className.substring(0, idx + ".accesscontext".length());
        }
        return className;
    }


    // ======================================================================
// COLLECT POLICIES (SAVE TO DB) - đồng nhất với UserInterfaceFragment
// ======================================================================
    public List<ResourcePolicyModel> collectSpecificPolicies() {

        List<ResourcePolicyModel> out = new ArrayList<>();
        Set<String> unique = new HashSet<>();

        // ---- CASE 1: Allow all ----
        if (Boolean.TRUE.equals(allowAllSpecific.getValue())) {
            ResourcePolicyModel all = metadata.create(ResourcePolicyModel.class);
            all.setId(UUID.randomUUID());
            all.setType("specific");
            all.setResource("*");
            all.setAction("Access");
            all.setEffect(ResourcePolicyEffect.ALLOW);
            all.setPolicyGroup("*"); // ✅ hiển thị group wildcard
            out.add(all);
            return out;
        }

        // ---- CASE 2: Collect từng leaf ----
        for (SpecificNode group : specificDc.getItems()) {
            for (SpecificNode leaf : group.getChildren()) {

                // chỉ xử lý leaf được Allow
                if (!"ALLOW".equals(leaf.getEffect()))
                    continue;

                // tạo key duy nhất để tránh trùng lặp
                String key = "specific|" + leaf.getName() + "|Access";
                if (!unique.add(key)) {
                    continue;
                }

                // ✅ tạo model đúng metadata
                ResourcePolicyModel p = metadata.create(ResourcePolicyModel.class);
                p.setId(UUID.randomUUID());
                p.setType("specific");
                p.setResource(leaf.getName());
                p.setAction("Access");
                p.setEffect(ResourcePolicyEffect.ALLOW);

                // ✅ gán policy group = group name (nếu có)
                String groupName = group.getName();
                if (groupName != null && !groupName.isBlank()) {
                    p.setPolicyGroup(groupName);
                } else {
                    p.setPolicyGroup(leaf.getName());
                }

                out.add(p);
            }
        }

        return out;
    }




}
