package com.vn.rm.rolemanage;

import com.google.common.base.Strings;
import com.vaadin.flow.router.Route;
import com.vn.rm.rolemanage.entityfragment.EntitiesFragment;
import com.vn.rm.rolemanage.specificfragment.SpecificFragment;
import com.vn.rm.rolemanage.userinterfacefragment.UserInterfaceFragment;
import io.jmix.core.DataManager;
import io.jmix.core.FetchPlan;
import io.jmix.core.Metadata;
import io.jmix.flowui.DialogWindows;
import io.jmix.flowui.component.checkboxgroup.JmixCheckboxGroup;
import io.jmix.flowui.component.grid.DataGrid;
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
    @ViewComponent
    private SpecificFragment specificFragment;
    @ViewComponent
    private DataGrid<ResourceRoleModel> childRolesTable;
    @ViewComponent
    private CollectionContainer<ResourceRoleModel> childRolesDc;
    @ViewComponent("saveAction")
    private Action saveAction;

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

    @Subscribe
    public void onInitEntity(InitEntityEvent<ResourceRoleModel> event) {
        ResourceRoleModel model = event.getEntity();
        model.setSource(RoleSourceType.DATABASE);
        model.setResourcePolicies(new ArrayList<>());
        model.setChildRoles(new HashSet<>());
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
            if (saveAction != null) saveAction.setVisible(false);
            if (childRolesTable != null) childRolesTable.getActions().forEach(a -> a.setEnabled(false));
        } else {
            setFormReadOnly(false);
            if (saveAction != null) saveAction.setVisible(true);
            if (childRolesTable != null) childRolesTable.getActions().forEach(a -> a.setEnabled(true));
        }
    }

    private void setFormReadOnly(boolean readOnly) {
        codeField.setReadOnly(readOnly);
        nameField.setReadOnly(readOnly);
        descriptionField.setReadOnly(readOnly);
        scopesField.setReadOnly(readOnly);
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

    @Subscribe(id = "childRolesDc", target = Target.DATA_CONTAINER)
    public void onChildRolesDcCollectionChange(CollectionContainer.CollectionChangeEvent<ResourceRoleModel> event) {
        Set<String> childRoles = childRolesDc.getItems().stream()
                .map(BaseRoleModel::getCode)
                .collect(Collectors.toSet());
        getEditedEntity().setChildRoles(childRoles);
    }

    @Subscribe("saveAction")
    public void onSaveAction(ActionPerformedEvent event) {
        ResourceRoleModel model = roleModelDc.getItem();
        if (model == null) return;
        if (RoleSourceType.ANNOTATED_CLASS.equals(model.getSource())) return;

        List<ResourcePolicyModel> allPolicies = collectAllPoliciesFromFragments(model);

        Map<String, ResourcePolicyModel> uniquePoliciesMap = new LinkedHashMap<>();
        for (ResourcePolicyModel p : allPolicies) {
            String key = policyKey(p.getType(), p.getResource(), p.getAction(), p.getEffect(), p.getPolicyGroup());
            uniquePoliciesMap.put(key, p);
        }
        List<ResourcePolicyModel> distinctPolicies = new ArrayList<>(uniquePoliciesMap.values());

        List<ResourcePolicyModel> finalPolicies = optimizeEntityPolicies(distinctPolicies);

        saveRoleUsingSaveContext(model, finalPolicies);

        close(StandardOutcome.SAVE);
    }

    private List<ResourcePolicyModel> optimizeEntityPolicies(List<ResourcePolicyModel> inputPolicies) {
        Set<String> wildcardActions = new HashSet<>();

        for (ResourcePolicyModel p : inputPolicies) {
            boolean isEntity = "entity".equalsIgnoreCase(p.getType());
            String resource = Objects.toString(p.getResource(), "").trim();

            if (isEntity && "*".equals(resource)) {
                if (p.getAction() != null) {
                    wildcardActions.add(p.getAction().trim().toLowerCase());
                }
            }
        }

        if (wildcardActions.isEmpty()) {
            return inputPolicies;
        }

        List<ResourcePolicyModel> optimized = new ArrayList<>();

        for (ResourcePolicyModel p : inputPolicies) {
            boolean isEntity = "entity".equalsIgnoreCase(p.getType());

            if (isEntity) {
                String resource = Objects.toString(p.getResource(), "").trim();
                String currentAction = Objects.toString(p.getAction(), "").trim().toLowerCase();

                boolean isWildcardRow = "*".equals(resource);
                boolean hasWildcardForThisAction = wildcardActions.contains(currentAction);

                if (!isWildcardRow && hasWildcardForThisAction) {
                    continue;
                }
            }
            optimized.add(p);
        }

        return optimized;
    }

    private void saveRoleUsingSaveContext(ResourceRoleModel model, List<ResourcePolicyModel> newPolicies) {
        ResourceRoleEntity dbRoleEntity = dataManager.load(ResourceRoleEntity.class)
                .query("select r from sec_ResourceRoleEntity r where r.code = :code")
                .parameter("code", model.getCode())
                .fetchPlan(fp -> fp.addFetchPlan(FetchPlan.BASE).add("resourcePolicies", FetchPlan.BASE))
                .optional()
                .orElseGet(() -> {
                    ResourceRoleEntity r = dataManager.create(ResourceRoleEntity.class);
                    r.setCode(model.getCode());
                    return r;
                });

        dbRoleEntity.setName(model.getName());
        dbRoleEntity.setDescription(model.getDescription());
        dbRoleEntity.setScopes(model.getScopes());
        dbRoleEntity.setChildRoles(model.getChildRoles());

        io.jmix.core.SaveContext saveContext = new io.jmix.core.SaveContext();

        List<ResourcePolicyEntity> oldPolicies = dbRoleEntity.getResourcePolicies();
        if (oldPolicies != null && !oldPolicies.isEmpty()) {
            saveContext.removing(new ArrayList<>(oldPolicies));
            oldPolicies.clear();
        } else {
            dbRoleEntity.setResourcePolicies(new ArrayList<>());
        }


        for (ResourcePolicyModel pm : newPolicies) {
            ResourcePolicyEntity entity = dataManager.create(ResourcePolicyEntity.class);
            entity.setRole(dbRoleEntity);
            entity.setType(pm.getType());
            entity.setResource(pm.getResource());
            entity.setAction(pm.getAction());
            entity.setEffect(pm.getEffect());
            entity.setPolicyGroup(pm.getPolicyGroup());
            dbRoleEntity.getResourcePolicies().add(entity);
        }

        saveContext.saving(dbRoleEntity);
        dataManager.save(saveContext);
    }

    private List<ResourcePolicyModel> collectAllPoliciesFromFragments(ResourceRoleModel model) {
        List<ResourcePolicyModel> all = new ArrayList<>();
        if (entitiesFragment != null) all.addAll(entitiesFragment.buildPoliciesFromMatrix());
        if (userInterfaceFragment != null) all.addAll(userInterfaceFragment.collectPoliciesFromTree());
        if (specificFragment != null) all.addAll(specificFragment.collectSpecificPolicies());
        return all;
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

    private static String policyKey(Object type, Object resource, Object action, Object effect, Object group) {
        return (Objects.toString(type, "") + "|" +
                Objects.toString(resource, "") + "|" +
                Objects.toString(action, "") + "|" +
                Objects.toString(effect, "") + "|" +
                Objects.toString(group, ""));
    }
}
