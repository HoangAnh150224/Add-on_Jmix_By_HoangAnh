package com.vn.rm.rolemanage;

import com.google.common.base.Strings;
import com.vaadin.flow.router.Route;
import com.vn.rm.rolemanage.entityfragment.EntitiesFragment;
import com.vn.rm.rolemanage.userinterfacefragment.UserInterfaceFragment;
import io.jmix.core.DataManager;
import io.jmix.core.Metadata;
import io.jmix.core.SaveContext;
import io.jmix.flowui.component.checkboxgroup.JmixCheckboxGroup;
import io.jmix.flowui.kit.action.Action;
import io.jmix.flowui.kit.action.ActionPerformedEvent;
import io.jmix.flowui.model.CollectionContainer;
import io.jmix.flowui.model.DataContext;
import io.jmix.flowui.model.InstanceContainer;
import io.jmix.flowui.view.*;
import io.jmix.flowui.view.navigation.UrlParamSerializer;
import io.jmix.security.model.*;
import io.jmix.security.role.ResourceRoleRepository;
import io.jmix.securitydata.entity.ResourcePolicyEntity;
import io.jmix.securitydata.entity.ResourceRoleEntity;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

@Route(value = "sec/resource-role-edit-view/:code", layout = DefaultMainViewParent.class)
@ViewController("rm_ResourceRoleEditView")
@ViewDescriptor("resource-role-edit-view.xml")
@EditedEntityContainer("roleModelDc")
public class ResourceRoleEditView extends StandardDetailView<ResourceRoleModel> {

    // ============================= UI components =============================
    @ViewComponent
    private io.jmix.flowui.component.textfield.TypedTextField<String> codeField;

    @ViewComponent
    private io.jmix.flowui.component.textfield.TypedTextField<String> nameField;

    @ViewComponent
    private io.jmix.flowui.component.textarea.JmixTextArea descriptionField;

    @ViewComponent
    private JmixCheckboxGroup<String> scopesField;

    @ViewComponent
    private DataContext dataContext;
    @ViewComponent
    private InstanceContainer<ResourceRoleModel> roleModelDc;

    @ViewComponent
    private CollectionContainer<ResourcePolicyModel> resourcePoliciesDc;

    @ViewComponent
    private EntitiesFragment entitiesFragment;

    @ViewComponent
    private UserInterfaceFragment userInterfaceFragment;

    // --- Inject Action Save để ẩn đi nếu là Read-only ---
    @ViewComponent("saveAction")
    private Action saveAction;

    // ================================ Services ===============================

    @Autowired
    private UrlParamSerializer urlParamSerializer;
    @Autowired
    private ResourceRoleRepository roleRepository;
    @Autowired
    private RoleModelConverter roleModelConverter;
    @Autowired
    private Metadata metadata;
    @Autowired
    private DataManager dataManager;

    // ============================== Lifecycle ================================

    @Subscribe
    public void onInitEntity(InitEntityEvent<ResourceRoleModel> event) {
        ResourceRoleModel model = event.getEntity();

        model.setSource(RoleSourceType.DATABASE);
        model.setResourcePolicies(new ArrayList<>());

        // Mặc định cho phép sửa (với role tạo mới)
        setFormReadOnly(false);
    }

    @Override
    protected String getRouteParamName() {
        return "code";
    }

    @Subscribe
    public void onInit(InitEvent event) {
        scopesField.setItems(Arrays.asList(SecurityScope.UI, SecurityScope.API));
    }

    @Subscribe
    public void onBeforeShow(BeforeShowEvent event) {
        ResourceRoleModel model = roleModelDc.getItemOrNull();
        if (model == null) {
            return;
        }

        // --- Check xem Role có phải annotated class không ---
        boolean isAnnotatedRole = RoleSourceType.ANNOTATED_CLASS.equals(model.getSource())
                || "Annotated class".equals(model.getSource());

        // 1. Cấu hình Fragment (Entities & Attributes)
        if (entitiesFragment != null) {
            entitiesFragment.setRoleReadOnly(isAnnotatedRole); // Truyền cờ xuống fragment

            List<ResourcePolicyModel> policies =
                    Optional.ofNullable(model.getResourcePolicies())
                            .map(ArrayList::new)
                            .orElseGet(ArrayList::new);
            entitiesFragment.initPolicies(policies);
        }

        // 2. Cấu hình UI & Menus
        if (userInterfaceFragment != null) {
            userInterfaceFragment.initUi(model);
        }
        resourcePoliciesDc.getMutableItems()
                .removeIf(p -> "DENY".equalsIgnoreCase(p.getEffect()));

        // 3. Cấu hình Form chính (Fields + Save Button)
        if (isAnnotatedRole) {
            setFormReadOnly(true);
            if (saveAction != null) {
                saveAction.setVisible(false); // Ẩn nút Save
            }
        } else {
            setFormReadOnly(false);
            if (saveAction != null) {
                saveAction.setVisible(true);
            }
        }
    }

    /**
     * Helper để bật/tắt chế độ chỉ đọc cho các ô nhập liệu chính
     */
    private void setFormReadOnly(boolean readOnly) {
        codeField.setReadOnly(readOnly);
        nameField.setReadOnly(readOnly);
        descriptionField.setReadOnly(readOnly);
        scopesField.setReadOnly(readOnly);
    }

    // ============================ Load entity ============================

    @Override
    protected void initExistingEntity(String serializedEntityCode) {
        String code = null;
        try {
            code = urlParamSerializer.deserialize(String.class, serializedEntityCode);
        } catch (Exception ignore) {
        }

        if (Strings.isNullOrEmpty(code)) {
            close(StandardOutcome.CLOSE);
            return;
        }

        // 1) Thử load role từ DB
        ResourceRoleEntity roleEntity = dataManager.load(ResourceRoleEntity.class)
                .query("select r from sec_ResourceRoleEntity r left join fetch r.resourcePolicies where r.code = :code")
                .parameter("code", code)
                .optional()
                .orElse(null);

        ResourceRoleModel model;

        if (roleEntity != null) {
            // Role từ database
            model = mapDbRoleToModel(roleEntity);
        } else {
            // 2) Nếu không có trong DB thì thử annotated role
            ResourceRole annotated = roleRepository.findRoleByCode(code);
            if (annotated == null) {
                close(StandardOutcome.CLOSE);
                return;
            }

            model = roleModelConverter.createResourceRoleModel(annotated);
            model.setSource(RoleSourceType.ANNOTATED_CLASS);

            if (model.getResourcePolicies() == null) {
                model.setResourcePolicies(new ArrayList<>());
            }
        }

        ResourceRoleModel merged = dataContext.merge(model);
        roleModelDc.setItem(merged);
        resourcePoliciesDc.setItems(
                Optional.ofNullable(merged.getResourcePolicies())
                        .map(ArrayList::new)
                        .orElseGet(ArrayList::new)
        );
    }

    // ============================== SAVE ==============================

    @Subscribe("saveAction")
    public void onSaveAction(ActionPerformedEvent event) {
        ResourceRoleModel model = roleModelDc.getItem();
        if (model == null) {
            return;
        }

        // --- BẢO VỆ: Nếu là Annotated Class thì tuyệt đối không cho lưu ---
        if (RoleSourceType.ANNOTATED_CLASS.equals(model.getSource())) {
            return;
        }

        // Gom hết policies từ 2 fragment
        List<ResourcePolicyModel> allPolicies = collectAllPoliciesFromFragments(model);
        model.setResourcePolicies(allPolicies);

        // Lưu xuống DB - vừa dùng cho tạo mới, vừa dùng cho sửa
        persistRoleToDb(model);

        close(StandardOutcome.SAVE);
    }

    private List<ResourcePolicyModel> collectAllPoliciesFromFragments(ResourceRoleModel model) {
        List<ResourcePolicyModel> all = new ArrayList<>();

        // --- Entities fragment
        if (entitiesFragment != null) {
            all.addAll(entitiesFragment.buildPoliciesFromMatrix());
        }

        // --- UI & Menu fragment
        if (userInterfaceFragment != null) {
            all.addAll(userInterfaceFragment.collectPoliciesFromTree());
        }

        // --- Làm sạch duplicates (nếu fragment trả cùng policy)
        Map<String, ResourcePolicyModel> cleaned = new LinkedHashMap<>();
        for (ResourcePolicyModel p : all) {
            String key = p.getType() + "|" + p.getResource() + "|" + p.getAction() + "|" + p.getEffect();
            cleaned.put(key, p);
        }

        return new ArrayList<>(cleaned.values());
    }

    // ======================= Mapping & persistence =======================

    private ResourceRoleModel mapDbRoleToModel(ResourceRoleEntity roleEntity) {
        ResourceRoleModel m = metadata.create(ResourceRoleModel.class);
        m.setCode(roleEntity.getCode());
        m.setName(roleEntity.getName());
        m.setDescription(roleEntity.getDescription());
        m.setScopes(roleEntity.getScopes() == null ? Set.of() : new HashSet<>(roleEntity.getScopes()));
        m.setSource(RoleSourceType.DATABASE);

        List<ResourcePolicyModel> ps = new ArrayList<>();
        if (roleEntity.getResourcePolicies() != null) {
            for (ResourcePolicyEntity pe : roleEntity.getResourcePolicies()) {
                ResourcePolicyModel p = metadata.create(ResourcePolicyModel.class);
                p.setType(pe.getType());
                p.setResource(pe.getResource());
                p.setAction(pe.getAction());
                p.setEffect(pe.getEffect());
                p.setPolicyGroup(pe.getPolicyGroup());
                ps.add(p);
            }
        }
        m.setResourcePolicies(ps);
        return m;
    }

    private void persistRoleToDb(ResourceRoleModel model) {
        String code = model.getCode();
        if (Strings.isNullOrEmpty(code)) {
            throw new IllegalStateException("Code không được rỗng.");
        }

        ResourceRoleEntity role = dataManager.load(ResourceRoleEntity.class)
                .query("select r from sec_ResourceRoleEntity r left join fetch r.resourcePolicies where r.code = :code")
                .parameter("code", code)
                .optional()
                .orElseGet(() -> dataManager.create(ResourceRoleEntity.class));

        role.setCode(code);
        role.setName(model.getName());
        role.setDescription(model.getDescription());
        role.setScopes(model.getScopes() == null ? Set.of() : new HashSet<>(model.getScopes()));

        Map<String, ResourcePolicyEntity> existing = new HashMap<>();
        if (role.getResourcePolicies() != null) {
            for (ResourcePolicyEntity pe : role.getResourcePolicies()) {
                existing.put(policyKey(pe.getType(), pe.getResource(), pe.getAction(), pe.getEffect(), pe.getPolicyGroup()), pe);
            }
        } else {
            role.setResourcePolicies(new ArrayList<>());
        }

        Set<String> keepKeys = new HashSet<>();
        List<ResourcePolicyEntity> toPersist = new ArrayList<>();

        for (ResourcePolicyModel p : Optional.ofNullable(model.getResourcePolicies()).orElseGet(List::of)) {
            String key = policyKey(p.getType(), p.getResource(), p.getAction(), p.getEffect(), p.getPolicyGroup());
            keepKeys.add(key);

            ResourcePolicyEntity pe = existing.get(key);
            if (pe == null) {
                pe = dataManager.create(ResourcePolicyEntity.class);
                pe.setRole(role);
                role.getResourcePolicies().add(pe);
            }

            pe.setType(p.getType());
            pe.setResource(p.getResource());
            pe.setAction(p.getAction());
            pe.setEffect(p.getEffect());
            pe.setPolicyGroup(p.getPolicyGroup());

            toPersist.add(pe);
        }

        List<ResourcePolicyEntity> toRemove = role.getResourcePolicies().stream()
                .filter(pe -> !keepKeys.contains(policyKey(pe.getType(), pe.getResource(), pe.getAction(), pe.getEffect(), pe.getPolicyGroup())))
                .toList();

        role.getResourcePolicies().removeIf(toRemove::contains);

        SaveContext ctx = new SaveContext();
        ctx.saving(role);
        toPersist.forEach(ctx::saving);
        toRemove.forEach(ctx::removing);
        dataManager.save(ctx);
    }

    private static String policyKey(Object type, Object resource, Object action, Object effect, Object group) {
        return (Objects.toString(type, "") + "|" +
                Objects.toString(resource, "") + "|" +
                Objects.toString(action, "") + "|" +
                Objects.toString(effect, "") + "|" +
                Objects.toString(group, ""));
    }
}