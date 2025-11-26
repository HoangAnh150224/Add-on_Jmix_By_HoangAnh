package com.vn.rm.rolesystem;

import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteParameters;
import com.vn.rm.rolemanage.ResourceRoleEditView;
import io.jmix.flowui.ViewNavigators;
import io.jmix.flowui.component.grid.DataGrid;
import io.jmix.flowui.kit.action.Action;
import io.jmix.flowui.kit.action.ActionPerformedEvent;
import io.jmix.flowui.view.*;
import io.jmix.flowui.view.navigation.UrlParamSerializer;
import io.jmix.security.model.ResourceRoleModel;
import io.jmix.security.role.RolePersistence;
import io.jmix.securityflowui.view.resourcerole.ResourceRoleModelListView;
import org.springframework.beans.factory.annotation.Autowired;

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
        ResourceRoleModel selected = roleModelsTable.getSingleSelectedItem();
        if (selected == null) return;

        String serialized = urlParamSerializer.serialize(selected.getCode());
        viewNavigators.view(this, ResourceRoleEditView.class)
                .withRouteParameters(new RouteParameters("code", serialized))
                .navigate();
    }


}