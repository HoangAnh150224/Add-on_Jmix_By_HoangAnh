package com.vn.rm.rolemanage;

import com.google.common.base.Strings;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.router.Route;
import com.vn.rm.rolemanage.entityfragment.EntitiesFragment;
import com.vn.rm.rolemanage.specificfragment.SpecificFragment;
import com.vn.rm.rolemanage.userinterfacefragment.UserInterfaceFragment;
import io.jmix.core.DataManager;
import io.jmix.core.FetchPlan;
import io.jmix.core.Messages;
import io.jmix.core.Metadata;
import io.jmix.core.SaveContext;
import io.jmix.flowui.DialogWindows;
import io.jmix.flowui.Notifications;
import io.jmix.flowui.component.checkboxgroup.JmixCheckboxGroup;
import io.jmix.flowui.component.grid.DataGrid;
import io.jmix.flowui.exception.ValidationException;
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
import io.jmix.securityflowui.view.resourcerole.ResourceRoleModelLookupView;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;
import java.util.stream.Collectors;

@Route(value = "sec/resource-role-edit-view/:code", layout = DefaultMainViewParent.class)
@ViewController("rm_ResourceRoleEditView")
@ViewDescriptor("resource-role-edit-view.xml")
@EditedEntityContainer("roleModelDc")
public class ResourceRoleEditView extends StandardDetailView<ResourceRoleModel> {

    @ViewComponent
    private io.jmix.flowui.component.textfield.TypedTextField<String> codeField;
    @ViewComponent
    private io.jmix.flowui.component.textfield.TypedTextField<String> nameField;
    @ViewComponent
    private io.jmix.flowui.component.textarea.JmixTextArea descriptionField;
    @ViewComponent
    private JmixCheckboxGroup<String> scopesField;

    public static final String ROUTE_PARAM_NAME = "code";
    @ViewComponent
    private DataContext dataContext;
    @ViewComponent
    private InstanceContainer<ResourceRoleModel> roleModelDc;
    @ViewComponent
    private CollectionContainer<ResourcePolicyModel> resourcePoliciesDc;
    @ViewComponent
    private CollectionContainer<ResourceRoleModel> childRolesDc;
    @ViewComponent
    private DataGrid<ResourceRoleModel> childRolesTable;

    @ViewComponent
    private EntitiesFragment entitiesFragment;
    @ViewComponent
    private UserInterfaceFragment userInterfaceFragment;
    @ViewComponent
    private SpecificFragment specificFragment;

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
    @Autowired
    private DialogWindows dialogWindows;
    @Autowired
    private Messages messages;
    @Autowired
    private Notifications notifications;

    // =================================================================================
    // 1. TRƯỚC KHI LƯU (PRE-SAVE): VALIDATION & GOM DỮ LIỆU
    // =================================================================================
    @Subscribe
    public void onBeforeSave(BeforeSaveEvent event) {
        ResourceRoleModel model = getEditedEntity();

        // --- A. VALIDATION (Chặn lưu nếu dữ liệu sai) ---
        if (RoleSourceType.ANNOTATED_CLASS.equals(model.getSource())) {
            event.preventSave();
            return;
        }
        if (Strings.isNullOrEmpty(model.getCode())) {
            showNotification("Lỗi: Code không được để trống", Notification.Position.TOP_END);
            codeField.focus();
            event.preventSave();
            return;
        }
        if (Strings.isNullOrEmpty(model.getName())) {
            showNotification("Lỗi: Name không được để trống", Notification.Position.TOP_END);
            nameField.focus();
            event.preventSave();
            return;
        }
        if (model.getScopes() == null || model.getScopes().isEmpty()) {
            showNotification("Lỗi: Phải chọn ít nhất một Scope", Notification.Position.TOP_END);
            event.preventSave();
            return;
        }

        // --- B. GOM DỮ LIỆU TỪ CÁC FRAGMENT ---
        List<ResourcePolicyModel> allPolicies = collectAllPoliciesFromFragments(model);

        // --- C. XỬ LÝ LOGIC WILDCARD (*) ---
        List<ResourcePolicyModel> finalPolicies = optimizeEntityPolicies(allPolicies);

        // --- D. GÁN VÀO MODEL ĐỂ CHUẨN BỊ CHO BƯỚC SAVE DELEGATE ---
        // Tại đây model chứa toàn bộ dữ liệu MỚI NHẤT từ màn hình
        model.setResourcePolicies(new ArrayList<>(finalPolicies));
    }

    // =================================================================================
    // 2. SAVE DELEGATE: LOGIC LƯU DATABASE (UPDATE ROLE, REPLACE POLICIES)
    // =================================================================================
    @Install(target = Target.DATA_CONTEXT)
    private Set<Object> saveDelegate(final SaveContext saveContext) {
        if (!isDatabaseSource()) {
            return Set.of();
        }

        ResourceRoleModel model = getEditedEntity();

        // -----------------------------------------------------------
        // BƯỚC 1: Load Role Entity thật từ Database (để Update, không tạo mới nếu đã có)
        // -----------------------------------------------------------
        ResourceRoleEntity dbRoleEntity = dataManager.load(ResourceRoleEntity.class)
                .query("select r from sec_ResourceRoleEntity r where r.code = :code")
                .parameter("code", model.getCode())
                // Fetch luôn resourcePolicies để tí nữa xóa
                .fetchPlan(fp -> fp.addFetchPlan(FetchPlan.BASE).add("resourcePolicies", FetchPlan.BASE))
                .optional()
                .orElseGet(() -> {
                    // Chỉ tạo mới object Entity nếu trong DB chưa có (trường hợp Create New)
                    ResourceRoleEntity r = dataManager.create(ResourceRoleEntity.class);
                    r.setCode(model.getCode());
                    return r;
                });

        // -----------------------------------------------------------
        // BƯỚC 2: Cập nhật thông tin Role (UPDATE)
        // -----------------------------------------------------------
        dbRoleEntity.setName(model.getName());
        dbRoleEntity.setDescription(model.getDescription());
        dbRoleEntity.setScopes(model.getScopes());
        dbRoleEntity.setChildRoles(model.getChildRoles());

        // Tạo SaveContext riêng để ta kiểm soát hoàn toàn việc Xóa/Thêm
        io.jmix.core.SaveContext customSaveContext = new io.jmix.core.SaveContext();

        // -----------------------------------------------------------
        // BƯỚC 3: XÓA SẠCH CÁC POLICY CŨ (DELETE)
        // -----------------------------------------------------------
        List<ResourcePolicyEntity> oldPolicies = dbRoleEntity.getResourcePolicies();
        if (oldPolicies != null && !oldPolicies.isEmpty()) {
            // Lệnh này báo cho JPA xóa các dòng này trong bảng sec_resource_policy
            customSaveContext.removing(new ArrayList<>(oldPolicies));
            // Xóa khỏi list trong memory để tránh lỗi
            oldPolicies.clear();
        } else {
            dbRoleEntity.setResourcePolicies(new ArrayList<>());
        }

        // -----------------------------------------------------------
        // BƯỚC 4: THÊM CÁC POLICY MỚI TỪ UI (INSERT)
        // -----------------------------------------------------------
        // Sửa lỗi Collection vs List: Dùng Collection vì Jmix trả về Collection
        Collection<ResourcePolicyModel> newPoliciesFromUi = model.getResourcePolicies();

        if (newPoliciesFromUi != null) {
            for (ResourcePolicyModel pm : newPoliciesFromUi) {
                // Tạo Entity Policy mới
                ResourcePolicyEntity entity = dataManager.create(ResourcePolicyEntity.class);
                entity.setRole(dbRoleEntity); // Gán vào cha
                entity.setType(pm.getType());
                entity.setResource(pm.getResource());
                entity.setAction(pm.getAction());
                entity.setEffect(pm.getEffect());
                entity.setPolicyGroup(pm.getPolicyGroup());

                // Thêm vào cha
                dbRoleEntity.getResourcePolicies().add(entity);

                // Báo lưu thằng con
                customSaveContext.saving(entity);
            }
        }

        // -----------------------------------------------------------
        // BƯỚC 5: LƯU (COMMIT)
        // -----------------------------------------------------------
        // Báo lưu thằng cha
        customSaveContext.saving(dbRoleEntity);

        // Thực thi xuống DB
        dataManager.save(customSaveContext);

        // Trả về model để UI biết là save thành công và đóng view
        return Set.of(model);
    }

    // =================================================================================
    // CÁC HÀM HỖ TRỢ (HELPER)
    // =================================================================================

    private boolean isDatabaseSource() {
        return RoleSourceType.DATABASE.equals(getEditedEntity().getSource());
    }

    private void showNotification(String message, Notification.Position position) {
        notifications.create(message)
                .withType(Notifications.Type.WARNING)
                .withPosition(position)
                .show();
    }

    private List<ResourcePolicyModel> collectAllPoliciesFromFragments(ResourceRoleModel model) {
        List<ResourcePolicyModel> all = new ArrayList<>();
        if (entitiesFragment != null) all.addAll(entitiesFragment.buildPoliciesFromMatrix());
        if (userInterfaceFragment != null) all.addAll(userInterfaceFragment.collectPoliciesFromTree());
        if (specificFragment != null) all.addAll(specificFragment.collectSpecificPolicies());
        return all;
    }

    private List<ResourcePolicyModel> optimizeEntityPolicies(List<ResourcePolicyModel> inputPolicies) {
        Set<String> wildcardActions = new HashSet<>();
        // Logic tìm các action có resource là "*"
        for (ResourcePolicyModel p : inputPolicies) {
            boolean isEntity = "entity".equalsIgnoreCase(p.getType());
            String resource = Objects.toString(p.getResource(), "").trim();

            if (isEntity && "*".equals(resource)) {
                if (p.getAction() != null) {
                    wildcardActions.add(p.getAction().trim().toLowerCase());
                }
            }
        }

        if (wildcardActions.isEmpty()) return inputPolicies;

        List<ResourcePolicyModel> optimized = new ArrayList<>();
        for (ResourcePolicyModel p : inputPolicies) {
            boolean isEntity = "entity".equalsIgnoreCase(p.getType());
            if (isEntity) {
                String resource = Objects.toString(p.getResource(), "").trim();
                String currentAction = Objects.toString(p.getAction(), "").trim().toLowerCase();
                boolean isWildcardRow = "*".equals(resource);
                boolean hasWildcardForThisAction = wildcardActions.contains(currentAction);

                // Nếu đã có dòng * cho action này thì không cần lưu dòng chi tiết nữa
                if (!isWildcardRow && hasWildcardForThisAction) {
                    continue;
                }
            }
            optimized.add(p);
        }
        return optimized;
    }

    // =================================================================================
    // LOGIC UI CHUẨN (GIỮ NGUYÊN)
    // =================================================================================

    @Subscribe("childRolesTable.add")
    public void onChildRolesTableAdd(ActionPerformedEvent event) {
        DialogWindow<ResourceRoleModelLookupView> lookupDialog = dialogWindows.lookup(childRolesTable)
                .withViewClass(ResourceRoleModelLookupView.class)
                .build();

        List<String> excludedRolesCodes = childRolesDc.getItems().stream()
                .map(BaseRoleModel::getCode)
                .collect(Collectors.toList());

        ResourceRoleModel edited = getEditedEntity();
        if (edited != null && edited.getCode() != null) {
            excludedRolesCodes.add(edited.getCode());
        }

        lookupDialog.getView().setExcludedRoles(excludedRolesCodes);
        lookupDialog.open();
    }

    @Subscribe(id = "childRolesDc", target = Target.DATA_CONTAINER)
    public void onChildRolesDcCollectionChange(CollectionContainer.CollectionChangeEvent<ResourceRoleModel> event) {
        Set<String> childRoles = childRolesDc.getItems().stream()
                .map(BaseRoleModel::getCode)
                .collect(Collectors.toSet());
        getEditedEntity().setChildRoles(childRoles);
    }

    @Subscribe
    public void onInitEntity(InitEntityEvent<ResourceRoleModel> event) {
        ResourceRoleModel model = event.getEntity();
        model.setSource(RoleSourceType.DATABASE);
        model.setResourcePolicies(new ArrayList<>());
        model.setChildRoles(new HashSet<>());
        setFormReadOnly(false);
    }

    @Subscribe
    public void onInit(InitEvent event) {
        scopesField.setItems(Arrays.asList(SecurityScope.UI, SecurityScope.API));
    }

    @Subscribe
    public void onBeforeShow(BeforeShowEvent event) {
        ResourceRoleModel model = roleModelDc.getItemOrNull();
        if (model == null) return;

        boolean isAnnotatedRole = RoleSourceType.ANNOTATED_CLASS.equals(model.getSource())
                || "Annotated class".equals(model.getSource());

        if (entitiesFragment != null) {
            entitiesFragment.setRoleReadOnly(isAnnotatedRole);
            List<ResourcePolicyModel> policies = Optional.ofNullable(model.getResourcePolicies())
                    .map(ArrayList::new).orElseGet(ArrayList::new);
            entitiesFragment.initPolicies(policies);
        }

        if (userInterfaceFragment != null) userInterfaceFragment.initUi(model);
        if (specificFragment != null) specificFragment.initSpecific(model);

        resourcePoliciesDc.getMutableItems().removeIf(p -> "DENY".equalsIgnoreCase(p.getEffect()));

        if (isAnnotatedRole) {
            setFormReadOnly(true);
            if (childRolesTable != null) childRolesTable.getActions().forEach(a -> a.setEnabled(false));
        } else {
            setFormReadOnly(false);
            if (!Strings.isNullOrEmpty(model.getCode())) {
                codeField.setReadOnly(true);
            }
            if (childRolesTable != null) childRolesTable.getActions().forEach(a -> a.setEnabled(true));
        }
    }

    private void setFormReadOnly(boolean readOnly) {
        codeField.setReadOnly(readOnly);
        nameField.setReadOnly(readOnly);
        descriptionField.setReadOnly(readOnly);
        scopesField.setReadOnly(readOnly);
    }

    @Install(to = "codeField", subject = "validator")
    private void codeFieldValidator(String value) {
        ResourceRoleModel editedEntity = getEditedEntity();
        boolean exist = roleRepository.getAllRoles().stream()
                .filter(resourceRole -> {
                    if (resourceRole.getCustomProperties().isEmpty()) {
                        return true;
                    }
                    return !resourceRole.getCustomProperties().get("databaseId")
                            .equals(editedEntity.getCustomProperties().get("databaseId"));
                })
                .anyMatch(resourceRole -> resourceRole.getCode().equals(value));
        if (exist) {
            throw new ValidationException(messages.getMessage("io.jmix.securityflowui.view.resourcerole/uniqueCode"));
        }
    }

    @Override
    protected String getRouteParamName() {
        return "code";
    }

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

        ResourceRoleEntity roleEntity = dataManager.load(ResourceRoleEntity.class)
                .query("select r from sec_ResourceRoleEntity r left join fetch r.resourcePolicies where r.code = :code")
                .parameter("code", code)
                .optional()
                .orElse(null);

        ResourceRoleModel model;

        if (roleEntity != null) {
            model = mapDbRoleToModel(roleEntity);
        } else {
            ResourceRole annotated = roleRepository.findRoleByCode(code);
            if (annotated == null) {
                close(StandardOutcome.CLOSE);
                return;
            }
            model = roleModelConverter.createResourceRoleModel(annotated);
            model.setSource(RoleSourceType.ANNOTATED_CLASS);
            if (model.getResourcePolicies() == null) model.setResourcePolicies(new ArrayList<>());
        }

        ResourceRoleModel merged = dataContext.merge(model);
        roleModelDc.setItem(merged);
        resourcePoliciesDc.setItems(Optional.ofNullable(merged.getResourcePolicies()).map(ArrayList::new).orElseGet(ArrayList::new));
        childRolesDc.mute();
        childRolesDc.setItems(loadChildRoleModels(merged));
        childRolesDc.unmute();
    }

    private List<ResourceRoleModel> loadChildRoleModels(ResourceRoleModel editedRoleModel) {
        if (editedRoleModel.getChildRoles() == null || editedRoleModel.getChildRoles().isEmpty()) {
            return Collections.emptyList();
        }
        List<ResourceRoleModel> childRoleModels = new ArrayList<>();
        for (String code : editedRoleModel.getChildRoles()) {
            ResourceRole child = roleRepository.findRoleByCode(code);
            if (child != null) {
                childRoleModels.add(roleModelConverter.createResourceRoleModel(child));
            }
        }
        return childRoleModels;
    }

    private ResourceRoleModel mapDbRoleToModel(ResourceRoleEntity roleEntity) {
        ResourceRoleModel m = metadata.create(ResourceRoleModel.class);
        m.setCode(roleEntity.getCode());
        m.setName(roleEntity.getName());
        m.setDescription(roleEntity.getDescription());
        m.setScopes(roleEntity.getScopes() == null ? Set.of() : new HashSet<>(roleEntity.getScopes()));
        m.setSource(RoleSourceType.DATABASE);
        m.setChildRoles(roleEntity.getChildRoles() == null ? new HashSet<>() : new HashSet<>(roleEntity.getChildRoles()));

        List<ResourcePolicyModel> ps = new ArrayList<>();
        if (roleEntity.getResourcePolicies() != null) {
            roleEntity.getResourcePolicies().forEach(pe -> {
                ResourcePolicyModel p = metadata.create(ResourcePolicyModel.class);
                p.setType(pe.getType());
                p.setResource(pe.getResource());
                p.setAction(pe.getAction());
                p.setEffect(pe.getEffect());
                p.setPolicyGroup(pe.getPolicyGroup());
                ps.add(p);
            });
        }
        m.setResourcePolicies(ps);
        return m;
    }
}