    package com.vn.rm.rolemanage.service;

    import com.google.common.base.Strings;
    import com.vn.rm.rolemanage.entityfragment.EntityMatrixRow;
    import com.vn.rm.rolemanage.userinterfacefragment.PolicyGroupNode;
    import io.jmix.core.Metadata;
    import io.jmix.flowui.fragment.FragmentDescriptor;
    import io.jmix.flowui.menu.MenuConfig;
    import io.jmix.flowui.menu.MenuItem;
    import io.jmix.flowui.view.ViewRegistry;
    import io.jmix.security.model.*;
    import io.jmix.security.role.ResourceRoleRepository;
    import io.jmix.securityflowui.view.resourcepolicy.AttributeResourceModel;
    import io.jmix.securityflowui.view.resourcepolicy.EntityAttributePolicyAction;
    import io.jmix.securityflowui.view.resourcepolicy.EntityPolicyAction;
    import io.jmix.securityflowui.view.resourcepolicy.ResourcePolicyViewUtils;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.boot.autoconfigure.SpringBootApplication;
    import org.springframework.context.ApplicationContext;
    import org.springframework.core.io.Resource;
    import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
    import org.springframework.core.type.AnnotationMetadata;
    import org.springframework.core.type.classreading.CachingMetadataReaderFactory;
    import org.springframework.core.type.classreading.MetadataReader;
    import org.springframework.stereotype.Component;

    import java.util.*;
    import java.util.stream.Collectors;

    @Component("rm_RoleManagerService")
    public class RoleManagerService {

        @Autowired
        private ResourcePolicyViewUtils resourcePolicyEditorUtils;

        @Autowired
        private Metadata metadata;
        @Autowired private ViewRegistry viewRegistry;
        @Autowired private MenuConfig menuConfig;
        @Autowired private ApplicationContext applicationContext;
        @Autowired
        private ResourceRoleRepository resourceRoleRepository;

        private ResourceRoleModel annotatedRole;

        public void setAnnotatedRole(ResourceRoleModel role) {
            this.annotatedRole = role;
        }



        public ResourceRole getRoleByCode(String code) {
            return resourceRoleRepository.findRoleByCode(code);
        }


        private Map<String, List<PolicyGroupNode>> leafIndex = new HashMap<>();

        private static final String ACT_CREATE = EntityPolicyAction.CREATE.getId();
        private static final String ACT_READ = EntityPolicyAction.READ.getId();
        private static final String ACT_UPDATE = EntityPolicyAction.UPDATE.getId();
        private static final String ACT_DELETE = EntityPolicyAction.DELETE.getId();
        private static final String ACT_ATTR_VIEW = EntityAttributePolicyAction.VIEW.getId();
        private static final String ACT_ATTR_MODIFY = EntityAttributePolicyAction.MODIFY.getId();

        /**
         * Tạo skeleton entity matrix (chưa apply policy).
         */
        public List<EntityMatrixRow> createMatrixEntity() {
            return resourcePolicyEditorUtils.getEntityOptionsMap().entrySet().stream()
                    .filter(e -> !"*".equals(e.getKey()))
                    .map(e -> {
                        EntityMatrixRow r = metadata.create(EntityMatrixRow.class);
                        r.setEntityName(e.getKey());
                        r.setEntityCaption(e.getValue());
                        return r;
                    })
                    .collect(Collectors.toList());
        }

        /**
         * Apply tập ResourcePolicyModel vào các dòng entity + preload attribute vào cache.
         */
        public void updateEntityMatrix(List<EntityMatrixRow> rows,
                                       Collection<ResourcePolicyModel> policies,
                                       Map<String, List<AttributeResourceModel>> attrCache) {
            if (rows == null || rows.isEmpty()) {
                return;
            }

            Map<String, Set<String>> entityPolicyMap = new HashMap<>();
            Map<String, Map<String, Set<String>>> attrPolicyMap = new HashMap<>();

            if (policies != null) {
                for (ResourcePolicyModel p : policies) {
                    if (p.getResource() == null
                            || !Objects.equals(p.getEffect(), ResourcePolicyEffect.ALLOW)) {
                        continue;
                    }

                    if (ResourcePolicyType.ENTITY.equals(p.getType())) {
                        entityPolicyMap
                                .computeIfAbsent(p.getResource(), k -> new HashSet<>())
                                .add(p.getAction());
                    } else if (ResourcePolicyType.ENTITY_ATTRIBUTE.equals(p.getType())) {
                        String res = p.getResource();
                        int dotIndex = res.lastIndexOf(".");
                        if (dotIndex > 0) {
                            String entity = res.substring(0, dotIndex);
                            String attr = res.substring(dotIndex + 1);
                            attrPolicyMap
                                    .computeIfAbsent(entity, k -> new HashMap<>())
                                    .computeIfAbsent(attr, k -> new HashSet<>())
                                    .add(p.getAction());
                        }
                    }
                }
            }

            // Global entity policies: "*"
            Set<String> globalActions = entityPolicyMap.getOrDefault("*", Collections.emptySet());

            for (EntityMatrixRow row : rows) {
                String entity = row.getEntityName();
                Set<String> actions = entityPolicyMap.getOrDefault(entity, Collections.emptySet());

                // Merge quyền riêng của entity và quyền global (*)
                row.setCanCreate(actions.contains(ACT_CREATE) || globalActions.contains(ACT_CREATE));
                row.setCanRead(actions.contains(ACT_READ) || globalActions.contains(ACT_READ));
                row.setCanUpdate(actions.contains(ACT_UPDATE) || globalActions.contains(ACT_UPDATE));
                row.setCanDelete(actions.contains(ACT_DELETE) || globalActions.contains(ACT_DELETE));

                // Đồng bộ allowAll theo CRUD
                syncAllowAll(row);

                // Attribute policies cho entity
                Map<String, Set<String>> entityAttrs = attrPolicyMap.getOrDefault(entity, Collections.emptyMap());

                List<AttributeResourceModel> attrRows;
                if (!attrCache.containsKey(entity)) {
                    attrRows = buildAttrRowsForEntity(entity);
                    applyAttrPoliciesToRows(attrRows, entityAttrs);
                    attrCache.put(entity, attrRows);
                } else {
                    attrRows = attrCache.get(entity);
                    applyAttrPoliciesToRows(attrRows, entityAttrs);
                }

                row.setAttributes(computeAttrSummaryFromRows(attrRows));
            }
        }

        /**
         * Đồng bộ cờ allowAll = true nếu và chỉ nếu 4 CRUD đều true.
         * Cho fragment gọi được nên để public.
         */
        public void syncAllowAll(EntityMatrixRow r) {
            boolean all = Boolean.TRUE.equals(r.getCanCreate())
                    && Boolean.TRUE.equals(r.getCanRead())
                    && Boolean.TRUE.equals(r.getCanUpdate())
                    && Boolean.TRUE.equals(r.getCanDelete());
            r.setAllowAll(all);
        }

        /**
         * Tạo danh sách attribute cho một entity (chưa apply policy, tất cả view/modify = false).
         */
        public List<AttributeResourceModel> buildAttrRowsForEntity(String entityName) {
            return resourcePolicyEditorUtils.getEntityAttributeOptionsMap(entityName).entrySet().stream()
                    .filter(e -> !"*".equals(e.getKey()))
                    .map(e -> {
                        AttributeResourceModel r = metadata.create(AttributeResourceModel.class);
                        r.setName(e.getKey());
                        r.setCaption(e.getValue());
                        return r;
                    })
                    .sorted(Comparator.comparing(AttributeResourceModel::getName, String.CASE_INSENSITIVE_ORDER))
                    .collect(Collectors.toList());
        }

        /**
         * Apply attr policies (wildcard + từng attribute) vào danh sách rows.
         */
        private void applyAttrPoliciesToRows(List<AttributeResourceModel> rows,
                                             Map<String, Set<String>> attrPolicies) {
            Set<String> wildCardActions = attrPolicies.getOrDefault("*", Collections.emptySet());
            boolean wildView = wildCardActions.contains(ACT_ATTR_VIEW);
            boolean wildModify = wildCardActions.contains(ACT_ATTR_MODIFY);

            for (AttributeResourceModel r : rows) {
                Set<String> specificActions = attrPolicies.getOrDefault(r.getName(), Collections.emptySet());
                r.setView(wildView || specificActions.contains(ACT_ATTR_VIEW));
                r.setModify(wildModify || specificActions.contains(ACT_ATTR_MODIFY));
            }
        }

        /**
         * Tính summary attributes: null / "*" / "attr1, attr2, ...".
         */
        public String computeAttrSummaryFromRows(List<AttributeResourceModel> rows) {
            if (rows == null || rows.isEmpty()) {
                return null;
            }

            boolean allView = true;
            boolean allModify = true;
            List<String> selected = new ArrayList<>();

            for (AttributeResourceModel r : rows) {
                boolean v = Boolean.TRUE.equals(r.getView());
                boolean m = Boolean.TRUE.equals(r.getModify());

                if (!v) {
                    allView = false;
                }
                if (!m) {
                    allModify = false;
                }

                if (v || m) {
                    selected.add(r.getName());
                }
            }

            if (allView || allModify) {
                return "*";
            }
            if (selected.isEmpty()) {
                return null;
            }

            selected.sort(String.CASE_INSENSITIVE_ORDER);
            return String.join(", ", selected);
        }

        /**
         * Build lại danh sách ResourcePolicyModel từ entity matrix + attr cache.
         */
        public List<ResourcePolicyModel> buildPoliciesFromMatrix(List<EntityMatrixRow> entityRows,
                                                                 Map<String, List<AttributeResourceModel>> attrCache) {
            List<ResourcePolicyModel> result = new ArrayList<>();

            // Lọc các dòng hợp lệ
            List<EntityMatrixRow> activeRows = entityRows.stream()
                    .filter(r -> !Strings.isNullOrEmpty(r.getEntityName()) && !"*".equals(r.getEntityName()))
                    .collect(Collectors.toList());

            // 1. Kiểm tra điều kiện "All Entities" (*)
            boolean allCreate = !activeRows.isEmpty()
                    && activeRows.stream().allMatch(r -> Boolean.TRUE.equals(r.getCanCreate()) || Boolean.TRUE.equals(r.getAllowAll()));
            boolean allRead = !activeRows.isEmpty()
                    && activeRows.stream().allMatch(r -> Boolean.TRUE.equals(r.getCanRead()) || Boolean.TRUE.equals(r.getAllowAll()));
            boolean allUpdate = !activeRows.isEmpty()
                    && activeRows.stream().allMatch(r -> Boolean.TRUE.equals(r.getCanUpdate()) || Boolean.TRUE.equals(r.getAllowAll()));
            boolean allDelete = !activeRows.isEmpty()
                    && activeRows.stream().allMatch(r -> Boolean.TRUE.equals(r.getCanDelete()) || Boolean.TRUE.equals(r.getAllowAll()));

            if (allCreate) {
                result.add(createPolicy(ResourcePolicyType.ENTITY, "*", ACT_CREATE));
            }
            if (allRead) {
                result.add(createPolicy(ResourcePolicyType.ENTITY, "*", ACT_READ));
            }
            if (allUpdate) {
                result.add(createPolicy(ResourcePolicyType.ENTITY, "*", ACT_UPDATE));
            }
            if (allDelete) {
                result.add(createPolicy(ResourcePolicyType.ENTITY, "*", ACT_DELETE));
            }

            // 2. Duyệt từng Entity Row
            for (EntityMatrixRow row : activeRows) {
                String entity = row.getEntityName();
                boolean allowAll = Boolean.TRUE.equals(row.getAllowAll());

                // 2.1 Entity Policies (CRUD) - bỏ qua những action đã gom vào "*"
                if (!allCreate && (allowAll || Boolean.TRUE.equals(row.getCanCreate()))) {
                    result.add(createPolicy(ResourcePolicyType.ENTITY, entity, ACT_CREATE));
                }
                if (!allRead && (allowAll || Boolean.TRUE.equals(row.getCanRead()))) {
                    result.add(createPolicy(ResourcePolicyType.ENTITY, entity, ACT_READ));
                }
                if (!allUpdate && (allowAll || Boolean.TRUE.equals(row.getCanUpdate()))) {
                    result.add(createPolicy(ResourcePolicyType.ENTITY, entity, ACT_UPDATE));
                }
                if (!allDelete && (allowAll || Boolean.TRUE.equals(row.getCanDelete()))) {
                    result.add(createPolicy(ResourcePolicyType.ENTITY, entity, ACT_DELETE));
                }

                // 2.2 Attribute Policies
                List<AttributeResourceModel> attrs = attrCache.getOrDefault(entity, Collections.emptyList());
                if (attrs.isEmpty()) {
                    continue;
                }

                boolean fullAttrView = attrs.stream().allMatch(a -> Boolean.TRUE.equals(a.getView()));
                boolean fullAttrModify = attrs.stream().allMatch(a -> Boolean.TRUE.equals(a.getModify()));

                if (fullAttrView) {
                    result.add(createAttrPolicy(entity, "*", ACT_ATTR_VIEW));
                }
                if (fullAttrModify) {
                    result.add(createAttrPolicy(entity, "*", ACT_ATTR_MODIFY));
                }

                // Nếu không phải full (*), tạo lẻ từng attribute
                if (!fullAttrView && !fullAttrModify) {
                    for (AttributeResourceModel attr : attrs) {
                        if (Boolean.TRUE.equals(attr.getView())) {
                            result.add(createAttrPolicy(entity, attr.getName(), ACT_ATTR_VIEW));
                        }
                        if (Boolean.TRUE.equals(attr.getModify())) {
                            result.add(createAttrPolicy(entity, attr.getName(), ACT_ATTR_MODIFY));
                        }
                    }
                }
            }
            return result;
        }

        /**
         * Cập nhật summary attributes cho 1 entity + sync lại cache.
         */
        public void updateEntityAttributesSummary(String entityName,
                                                  List<EntityMatrixRow> entityRows,
                                                  List<AttributeResourceModel> currentAttrRows,
                                                  Map<String, List<AttributeResourceModel>> attrCache) {
            if (Strings.isNullOrEmpty(entityName) || entityRows == null) {
                return;
            }

            entityRows.stream()
                    .filter(r -> entityName.equals(r.getEntityName()))
                    .findFirst()
                    .ifPresent(row -> {
                        String summary = computeAttrSummaryFromRows(currentAttrRows);
                        row.setAttributes(summary);
                        attrCache.put(entityName, new ArrayList<>(currentAttrRows != null ? currentAttrRows : List.of()));
                    });
        }

        // --- Helpers ---
        // --- Helpers ---

        public ResourcePolicyModel createPolicy(String type, String resource, String action) {
            ResourcePolicyModel p = metadata.create(ResourcePolicyModel.class);
            p.setType(type);
            p.setResource(resource);
            p.setAction(action);
            p.setEffect(ResourcePolicyEffect.ALLOW);
            p.setPolicyGroup(resource.endsWith("*") ? null : resource); // Group theo Entity
            return p;
        }

        private ResourcePolicyModel createAttrPolicy(String entity, String attr, String action) {
            ResourcePolicyModel p = metadata.create(ResourcePolicyModel.class);
            p.setType(ResourcePolicyType.ENTITY_ATTRIBUTE);
            p.setResource(entity + "." + attr);
            p.setAction(action);
            p.setEffect(ResourcePolicyEffect.ALLOW);
            p.setPolicyGroup(entity);
            return p;
        }


        /**
         * Tạo key duy nhất cho leaf bằng resource + action.
         */
        public String buildLeafKey(PolicyGroupNode node) {
            return buildLeafKey(node.getResource(), node.getAction(), node.getType());
        }

        /**
         * Trả về "resource|action" để dùng làm key đồng bộ leaf.
         */
        public String buildLeafKey(String resource, String action, String type) {

            if (resource == null || action == null)
                return null;

            // MENU có key riêng -> không trùng với SCREEN
            if ("menu".equalsIgnoreCase(type)) {
                return resource + "|" + action.toLowerCase() + "|menu";
            }

            // SCREEN key chuẩn (để applyPoliciesFromModel match)
            return resource + "|" + action.toLowerCase();
        }

        /**
         * Nén cây: gộp các folder 1-1 nếu không có leaf bên trong.
         */
        public PolicyGroupNode compress(PolicyGroupNode node) {

            if (!node.getGroup())
                return node;

            List<PolicyGroupNode> newChildren = new ArrayList<>();
            for (PolicyGroupNode c : node.getChildren())
                newChildren.add(compress(c));

            node.setChildren(newChildren);

            // 🔥 KHÔNG merge nếu node có leaf con → giữ group để leaf nằm bên trong!
            boolean hasLeaf = node.getChildren().stream().anyMatch(n -> !n.getGroup());
            if (hasLeaf)
                return node;

            // merge group 1-1
            if (node.getChildren().size() == 1 && node.getChildren().get(0).getGroup()) {
                PolicyGroupNode only = node.getChildren().get(0);
                if (!"View Access".equals(node.getName()))
                    only.setName(node.getName() + "." + only.getName());
                return only;
            }

            return node;
        }
        /**
         * Index toàn bộ leaf trong cây để đồng bộ trạng thái allow/deny.
         */
        public void indexLeaves(PolicyGroupNode node) {
            if (node.isLeaf()) {
                String key = buildLeafKey(node.getResource(), node.getAction(), node.getType());
                if (key != null) {
                    leafIndex.computeIfAbsent(key, k -> new ArrayList<>()).add(node);
                }
            }

            for (PolicyGroupNode c : node.getChildren())
                indexLeaves(c);
        }
        /**
         * Xây dựng cây View Access:
         *  - phân cấp theo package
         *  - gắn leaf view
         *  - gắn leaf menu nếu view nằm trong menu.
         */
        public void buildViewsTree(PolicyGroupNode root, Map<String, List<MenuItem>> viewMenuMap) {

            Map<String, String> classToViewId = new LinkedHashMap<>();

            viewRegistry.getViewInfos().forEach(info -> {
                if (info.getControllerClass() == null)
                    return;

                String className = info.getControllerClass().getName();
                String viewId = info.getId();

                classToViewId.compute(className, (key, existing) ->
                        selectPreferredViewId(existing, viewId));
            });

            Map<String, String> fragments = scanFragments();

            // Xử lý View
            for (Map.Entry<String, String> entry : classToViewId.entrySet()) {
                String className = entry.getKey();
                String viewId = entry.getValue();

                PolicyGroupNode parent = buildPackageTree(root, className);

                List<MenuItem> menuItems = viewMenuMap.get(viewId);
                if (menuItems != null && !menuItems.isEmpty()) {
                    boolean singleMenu = menuItems.size() == 1;
                    for (MenuItem menuItem : menuItems) {
                        PolicyGroupNode menuFolder = ensureMenuFolder(parent, menuItem, singleMenu);
                        addLeaf(menuFolder, viewId, "(View)", Collections.singletonList(menuItem));
                    }
                    continue;
                }

                addLeaf(parent, viewId, "(View)", Collections.emptyList());
            }

            // Xử lý Fragment
            for (String className : fragments.values()) {
                PolicyGroupNode parent = buildPackageTree(root, className);

                String simple = className.substring(className.lastIndexOf('.') + 1);
                addLeaf(parent, simple, "(Fragment)", Collections.emptyList());
            }
        }

        /**
         * Quét classpath để lấy danh sách fragment có @FragmentDescriptor.
         */
        private Map<String, String> scanFragments() {
            Map<String, String> result = new HashMap<>();
            try {
                String basePackage = applicationContext.getBeansWithAnnotation(SpringBootApplication.class)
                        .values().iterator().next()
                        .getClass().getPackageName();

                PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
                String path = "classpath*:" + basePackage.replace('.', '/') + "/**/*.class";

                Resource[] resources = resolver.getResources(path);
                CachingMetadataReaderFactory factory = new CachingMetadataReaderFactory();

                for (Resource r : resources) {
                    MetadataReader reader = factory.getMetadataReader(r);
                    AnnotationMetadata meta = reader.getAnnotationMetadata();

                    // fragment nhưng KHÔNG phải view
                    if (meta.hasAnnotation(FragmentDescriptor.class.getName()) &&
                            !meta.hasAnnotation("io.jmix.flowui.view.ViewController")) {

                        String className = reader.getClassMetadata().getClassName();
                        result.put(
                                className.substring(className.lastIndexOf('.') + 1),
                                className
                        );
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
            return result;
        }
        /**
         * Tạo các folder theo package từ className.
         */
        private PolicyGroupNode buildPackageTree(PolicyGroupNode root, String className) {
            String[] parts = className.split("\\.");
            PolicyGroupNode cur = root;

            for (int i = 0; i < parts.length - 1; i++) {
                String folder = parts[i];

                PolicyGroupNode exist = cur.getChildren().stream()
                        .filter(f -> f.getGroup() && f.getName().equals(folder))
                        .findFirst().orElse(null);

                if (exist == null) {
                    exist = new PolicyGroupNode(folder, true);
                    exist.setParent(cur);
                    cur.getChildren().add(exist);
                }
                cur = exist;
            }
            return cur;
        }


        private void addLeaf(PolicyGroupNode parent, String viewId, String meta, List<MenuItem> menuItems) {

            boolean isAnnotated = isAnnotatedView(viewId);

            // -------------------------------------------------------
            // CASE 1: View NẰM TRONG MENU → tạo MENU leaf + VIEW leaf
            // -------------------------------------------------------
            if (menuItems != null && !menuItems.isEmpty()) {

                boolean singleMenu = menuItems.size() == 1;

                for (MenuItem menuItem : menuItems) {

                    String caption = singleMenu
                            ? "Allow in menu"
                            : "Allow in menu (" + menuItem.getId() + ")";

                    PolicyGroupNode allowMenu = new PolicyGroupNode(caption, false);
                    allowMenu.setType("menu");
                    allowMenu.setResource(viewId);      // ✔ MUST USE VIEW ID (sync key)
                    allowMenu.setAction("Access");
                    allowMenu.setAnnotated(isAnnotated);
                    allowMenu.setParent(parent);

                    parent.getChildren().add(allowMenu);
                }

                // VIEW leaf
                PolicyGroupNode allowView = new PolicyGroupNode("View: " + viewId, false);
                allowView.setType("screen");
                allowView.setResource(viewId);          // ✔ same key
                allowView.setAction("Access");
                allowView.setMeta(meta);
                allowView.setAnnotated(isAnnotated);
                allowView.setParent(parent);

                parent.getChildren().add(allowView);
                return;
            }

            // -------------------------------------------------------
            // CASE 2: View KHÔNG trong menu → chỉ VIEW leaf
            // -------------------------------------------------------
            PolicyGroupNode leaf = new PolicyGroupNode(viewId, false);
            leaf.setType("screen");
            leaf.setResource(viewId);
            leaf.setAction("Access");
            leaf.setMeta(meta);
            leaf.setAnnotated(isAnnotated);
            leaf.setParent(parent);

            parent.getChildren().add(leaf);
        }


        /**
         * Tạo đầy đủ folder menu hierarchy từ một MenuItem.
         */
        private PolicyGroupNode ensureMenuFolder(PolicyGroupNode parent, MenuItem item, boolean singleMenuGroup) {
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
                        .findFirst().orElse(null);

                if (existing == null) {
                    existing = new PolicyGroupNode(caption, true);
                    existing.setType("MENU");
                    existing.setParent(curNode);
                    curNode.getChildren().add(existing);
                }
                curNode = existing;
            }

            if (!singleMenuGroup) {
                String leafName = item.getId() + " (menu)";

                PolicyGroupNode existingLeaf = curNode.getChildren().stream()
                        .filter(n -> !Boolean.TRUE.equals(n.getGroup()) && leafName.equals(n.getName()))
                        .findFirst().orElse(null);

                if (existingLeaf == null) {
                    PolicyGroupNode marker = new PolicyGroupNode(leafName, false);
                    marker.setType("MENU");
                    marker.setResource(item.getId());
                    marker.setAction("menu");
                    marker.setParent(curNode);
                    curNode.getChildren().add(marker);
                    return marker;
                }
            }

            return curNode;
        }
        /**
         * Chọn viewId ưu tiên (viewId custom được ưu tiên hơn).
         */
        private String selectPreferredViewId(String existing, String candidate) {
            if (existing == null)
                return candidate;

            boolean existingCustom = isCustomViewId(existing);
            boolean candidateCustom = isCustomViewId(candidate);

            if (candidateCustom && !existingCustom)
                return candidate;

            return existing;
        }
        /**
         * Kiểm tra viewId có phải dạng custom hay không.
         */
        private boolean isCustomViewId(String viewId) {
            if (viewId == null || viewId.isEmpty())
                return false;
            return viewId.contains(".") || viewId.contains("_") || Character.isLowerCase(viewId.charAt(0));
        }
        /**
         * Xây dựng toàn bộ cây Menu Access từ MenuConfig.
         */
        public void buildMenuTree(PolicyGroupNode menuRoot) {

            for (MenuItem root : menuConfig.getRootItems())
                addMenuNode(menuRoot, root);
        }
        /**
         * Thêm node menu:
         *  - nếu có view → thêm Allow Menu + View
         *  - nếu có child → xây tiếp
         *  - nếu không có gì → tạo leaf menu.
         */
        /**
         * Build cây Menu Access – nhưng MENU leaf phải dùng viewId để sync.
         * Nếu item không có view → chỉ tạo leaf menu THƯỜNG (không sync được).
         */
        private void addMenuNode(PolicyGroupNode parentNode, MenuItem item) {

            String caption = item.getView() != null ? item.getView() : item.getId();

            PolicyGroupNode groupNode = new PolicyGroupNode(caption, true);
            groupNode.setType("menu");
            groupNode.setParent(parentNode);
            parentNode.getChildren().add(groupNode);

            boolean hasView = item.getView() != null;
            boolean hasChildren = !item.getChildren().isEmpty();

            // ----------------------------------------------------
            // CASE 1: Menu item có VIEW → tạo 2 leaf:
            //   - MENU leaf (menu, Access, resource=viewId)
            //   - VIEW leaf (screen, Access, resource=viewId)
            // ----------------------------------------------------
            if (hasView) {

                String viewId = item.getView();

                // MENU leaf
                PolicyGroupNode allowMenu = new PolicyGroupNode("Allow in menu", false);
                allowMenu.setType("menu");
                allowMenu.setResource(viewId);     // ✔ MUST USE viewId
                allowMenu.setAction("Access");
                allowMenu.setParent(groupNode);
                groupNode.getChildren().add(allowMenu);

                // VIEW leaf
                PolicyGroupNode allowView = new PolicyGroupNode("View: " + viewId, false);
                allowView.setType("screen");
                allowView.setResource(viewId);     // ✔ same key as menu
                allowView.setAction("Access");
                allowView.setParent(groupNode);
                groupNode.getChildren().add(allowView);
            }

            // ----------------------------------------------------
            // CASE 2: Có children → build tiếp
            // ----------------------------------------------------
            if (hasChildren) {
                for (MenuItem c : item.getChildren())
                    addMenuNode(groupNode, c);
                return;
            }


            if (!hasView && !hasChildren) {
                PolicyGroupNode leaf = new PolicyGroupNode(caption, false);
                leaf.setType("menu");

                // 🔥 FIX: Nếu menu có view → dùng viewId để sync VIEW <-> MENU
                String res = item.getView() != null ? item.getView() : item.getId();
                leaf.setResource(res);

                leaf.setAction("Access");
                leaf.setParent(groupNode);
                groupNode.getChildren().add(leaf);
            }

        }


   
        public void collect(PolicyGroupNode node, List<ResourcePolicyModel> list) {

            if (node.isLeaf() && "ALLOW".equals(node.getEffect())) {

                ResourcePolicyModel p = new ResourcePolicyModel();
                p.setId(UUID.randomUUID());
                p.setType(node.getType());
                p.setResource(node.getResource());
                p.setAction(node.getAction());
                p.setEffect("ALLOW");

                list.add(p);
            }

            for (PolicyGroupNode c : node.getChildren())
                collect(c, list);
        }
        /**
         * MENU ↔ VIEW sync đúng logic
         *
         * - MENU tick Allow → ép VIEW Allow
         * - MENU tick Deny → VIEW về trạng thái blank (không ép deny)
         *
         * - VIEW tick Allow/Deny → CHỈ sync VIEW ↔ VIEW (không sync MENU)
         */
        public void syncLinkedLeaves(PolicyGroupNode node, boolean allow) {

            boolean isMenu = "menu".equalsIgnoreCase(node.getType());
            boolean isView = "screen".equalsIgnoreCase(node.getType());

            String keyScreen = buildLeafKey(node.getResource(), node.getAction(), "screen");
            String keyMenu   = buildLeafKey(node.getResource(), node.getAction(), "menu");

            // ✅ gom tất cả nodes liên quan cùng resource/action
            List<PolicyGroupNode> linked = new ArrayList<>();
            List<PolicyGroupNode> screenNodes = getNodesByKey(keyScreen);
            List<PolicyGroupNode> menuNodes = getNodesByKey(keyMenu);
            if (screenNodes != null) linked.addAll(screenNodes);
            if (menuNodes != null) linked.addAll(menuNodes);

            if (linked.isEmpty()) {
                applyState(node, allow);
                return;
            }

            // ================================
            // CASE 1: MENU → ảnh hưởng VIEW
            // ================================
            if (isMenu) {
                for (PolicyGroupNode target : linked) {
                    if ("menu".equalsIgnoreCase(target.getType())) {
                        // MENU ↔ MENU sync đầy đủ
                        target.setEffect(allow ? "ALLOW" : null);
                        target.setAllow(allow);
                        target.setDeny(!allow);
                    }

                    if ("screen".equalsIgnoreCase(target.getType())) {
                        if (allow) {
                            // ✅ MENU = ALLOW → VIEW = ép ALLOW luôn
                            target.setEffect("ALLOW");
                            target.setAllow(true);
                            target.setDeny(false);
                        } else {
                            // ❌ MENU = DENY → VIEW giữ nguyên (không ép deny)
                        }
                    }
                }

                applyState(node, allow);
                return;
            }

            // ================================
            // CASE 2: VIEW → chỉ sync VIEW ↔ VIEW
            // ================================
            if (isView) {
                for (PolicyGroupNode target : linked) {
                    if ("screen".equalsIgnoreCase(target.getType())) {
                        target.setEffect(allow ? "ALLOW" : null);
                        target.setAllow(allow);
                        target.setDeny(!allow);
                    }
                }

                applyState(node, allow);
                return;
            }

            // fallback
            applyState(node, allow);
        }


        public boolean isViewLockedByMenu(PolicyGroupNode viewNode) {

            if (!"screen".equalsIgnoreCase(viewNode.getType()))
                return false;

            // ✅ lấy cả key của screen và menu
            String keyScreen = buildLeafKey(viewNode.getResource(), viewNode.getAction(), "screen");
            String keyMenu   = buildLeafKey(viewNode.getResource(), viewNode.getAction(), "menu");

            List<PolicyGroupNode> linked = new ArrayList<>();

            List<PolicyGroupNode> screenNodes = getNodesByKey(keyScreen);
            List<PolicyGroupNode> menuNodes = getNodesByKey(keyMenu);

            if (screenNodes != null) linked.addAll(screenNodes);
            if (menuNodes != null) linked.addAll(menuNodes);

            if (linked.isEmpty()) return false;

            // ✅ Có ít nhất 1 menu ALLOW → khóa view
            return linked.stream().anyMatch(n ->
                    "menu".equalsIgnoreCase(n.getType()) &&
                            "ALLOW".equals(n.getEffect())
            );
        }

        /**
         * Cập nhật trạng thái allow/deny cho một leaf.
         */
        public void applyState(PolicyGroupNode node, boolean allow) {

            if (allow) {
                // ALLOW → lưu DB
                node.setEffect("ALLOW");
                node.setAllow(true);
                node.setDeny(false);
            } else {
                // DENY → chỉ hiển thị UI, không lưu DB
                node.setEffect(null);   // ❗ không gán "DENY"
                node.setAllow(false);
                node.setDeny(true);     // ❗ UI tick deny
            }
        }

        /**
         * Map viewId → danh sách MenuItem chứa view đó.
         */
        public Map<String, List<MenuItem>> buildViewMenuMap() {
            Map<String, List<MenuItem>> map = new HashMap<>();
            for (MenuItem root : menuConfig.getRootItems()) {
                collectMenuItems(root, map);
            }
            return map;
        }

        /**
         * Thu thập toàn bộ menuItem có chứa view vào map.
         */
        private void collectMenuItems(MenuItem item, Map<String, List<MenuItem>> map) {
            if (item.getView() != null) {
                map.computeIfAbsent(item.getView(), k -> new ArrayList<>()).add(item);
            }

            for (MenuItem child : item.getChildren()) {
                collectMenuItems(child, map);
            }
        }
        public void clearIndex() {
            leafIndex.clear();
        }
        public Map<String, List<PolicyGroupNode>> getLeafIndex() {
            return leafIndex;
        }
        public Collection<PolicyGroupNode> getAllIndexedLeaves() {
            List<PolicyGroupNode> result = new ArrayList<>();
            for (List<PolicyGroupNode> list : leafIndex.values()) {
                result.addAll(list);
            }
            return result;
        }

        public List<PolicyGroupNode> getNodesByKey(String key) {
            if (key == null) return null;
            return leafIndex.get(key);
        }

        private boolean isAnnotatedView(String viewId) {

            if (annotatedRole == null)
                return false;

            return annotatedRole.getResourcePolicies().stream()
                    .anyMatch(p ->
                            ResourcePolicyEffect.ALLOW.equals(p.getEffect())
                                    && "screen".equalsIgnoreCase(p.getType())
                                    && ("*".equals(p.getResource()) || p.getResource().equals(viewId))
                    );
        }

        public ResourceRoleModel convertAnnotatedToModel(ResourceRole runtimeRole) {

            if (runtimeRole == null)
                return null;

            ResourceRoleModel model = new ResourceRoleModel();
            model.setCode(runtimeRole.getCode());
            model.setName(runtimeRole.getName());
            model.setDescription(runtimeRole.getDescription());
            model.setSource(RoleSourceType.ANNOTATED_CLASS);
            model.setScopes(runtimeRole.getScopes());

            // Copy policies
            List<ResourcePolicyModel> policies = runtimeRole.getResourcePolicies().stream()
                    .map(p -> {
                        ResourcePolicyModel m = new ResourcePolicyModel();
                        m.setType(p.getType());
                        m.setResource(p.getResource());
                        m.setAction(p.getAction());
                        m.setEffect(p.getEffect());
                        m.setPolicyGroup(p.getPolicyGroup());
                        return m;
                    })
                    .collect(Collectors.toList());

            model.setResourcePolicies(policies);

            return model;
        }

    }
