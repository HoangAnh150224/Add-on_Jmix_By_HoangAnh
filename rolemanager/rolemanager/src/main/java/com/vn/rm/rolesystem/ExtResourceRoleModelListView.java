package com.vn.rm.rolesystem;

import com.vaadin.flow.component.AbstractField;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteParameters;
import com.vn.rm.rolemanage.ResourceRoleEditView;
import io.jmix.core.LoadContext;
import io.jmix.flowui.ViewNavigators;
import io.jmix.flowui.component.grid.DataGrid;
import io.jmix.flowui.component.textfield.TypedTextField;
import io.jmix.flowui.kit.action.Action;
import io.jmix.flowui.kit.action.ActionPerformedEvent;
import io.jmix.flowui.model.CollectionLoader;
import io.jmix.flowui.view.*;
import io.jmix.flowui.view.navigation.UrlParamSerializer;
import io.jmix.security.model.ResourceRole;
import io.jmix.security.model.ResourceRoleModel;
import io.jmix.security.model.RoleModelConverter;
import io.jmix.security.role.ResourceRoleRepository;
import io.jmix.security.role.RolePersistence;
import io.jmix.securityflowui.view.resourcerole.ResourceRoleModelDetailView;
import io.jmix.securityflowui.view.resourcerole.ResourceRoleModelListView;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import static io.jmix.flowui.view.StandardDetailView.NEW_ENTITY_ID;

@Route(value = "sec/extresourcerolemodels", layout = DefaultMainViewParent.class)
@ViewController(id = "ext_sec_ResourceRoleModel.list")
@ViewDescriptor(path = "ext-resource-role-model-list-view.xml")
@LookupComponent("roleModelsTable")
public class ExtResourceRoleModelListView extends ResourceRoleModelListView {
    @Autowired
    private ViewNavigators viewNavigators;


    @ViewComponent
    private DataGrid<ResourceRoleModel> roleModelsTable;

    @Autowired
    private UrlParamSerializer urlParamSerializer;

    @Autowired(required = false)
    private RolePersistence rolePersistence;

    @ViewComponent
    private CollectionLoader<ResourceRoleModel> roleModelsDl;
    @Autowired
    private ResourceRoleRepository resourceRoleRepository;
    @Autowired
    private RoleModelConverter roleModelConverter;
    @ViewComponent
    private TypedTextField<Object> nameFilterField;

    @Subscribe
    public void onInit(InitEvent event) {
        initActions();
    }

    private void initActions() {
        if (rolePersistence == null) {
            for (Action action : roleModelsTable.getActions()) {
                if (!action.getId().equals("edit")) {
                    action.setVisible(false);
                }
            }
        }
    }

    @Subscribe("roleModelsTable.createCustomRole")
    public void onRoleModelsTableCreateCustomRole(final ActionPerformedEvent event) {
        viewNavigators.view(this, ResourceRoleEditView.class)
                .withRouteParameters(new RouteParameters("code", NEW_ENTITY_ID))
                .navigate();
    }

    @Subscribe("roleModelsTable.editCustomRole")
    public void onRoleModelsTableEditCustomRole(ActionPerformedEvent e) {
        ResourceRoleModel item = roleModelsTable.getSingleSelectedItem();
        if (item == null) return;

        viewNavigators.view(this, ResourceRoleEditView.class)
                .withRouteParameters(new RouteParameters("code", item.getCode()))
                .navigate();
    }

    @Subscribe("nameFilterField")
    public void onNameFilterFieldComponentValueChange(final AbstractField.ComponentValueChangeEvent<TypedTextField<?>, ?> event) {
        roleModelsDl.load();

    }
    @Install(to = "roleModelsDl", target = Target.DATA_LOADER)
    protected List<ResourceRoleModel> roleModelsDlLoadDelegate(final LoadContext<ResourceRoleModel> loadContext) {
        Collection<ResourceRole> allRoles = resourceRoleRepository.getAllRoles();

        String filterValue = nameFilterField.getValue();

        return allRoles.stream()
                .filter(role -> {
                    // Nếu ô tìm kiếm trống -> lấy hết
                    if (StringUtils.isBlank(filterValue)) return true;

                    // Lấy tên role, nếu null thì gán chuỗi rỗng để không bị lỗi
                    String name = role.getName() != null ? role.getName() : "";

                    // CHỈ LỌC THEO TÊN (bỏ qua Code)
                    return StringUtils.containsIgnoreCase(name, filterValue);
                })
                .map(role -> roleModelConverter.createResourceRoleModel(role))
                .sorted(Comparator.comparing(ResourceRoleModel::getName))
                .collect(Collectors.toList());
    }
}