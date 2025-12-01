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
import io.jmix.security.model.RoleSource;
import io.jmix.security.role.RolePersistence;
import io.jmix.securityflowui.view.resourcerole.ResourceRoleModelListView;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;

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

    /**
     * Ẩn/bật các action gốc và custom tùy theo có RolePersistence hay không.
     */
    private void initActions() {
        if (rolePersistence == null) {
            // Không có database role → ẩn toàn bộ action thao tác role
            for (Action action : roleModelsTable.getActions()) {
                String id = action.getId();
                if ("create".equals(id)
                        || "edit".equals(id)
                        || "remove".equals(id)
                        || "assignToUsers".equals(id)
                        || "exportJSON".equals(id)
                        || "exportZIP".equals(id)
                        || "createCustomRole".equals(id)
                        || "editCustomRole".equals(id)) {
                    action.setVisible(false);
                }
            }
        } else {
            // Có database role → ẩn create/edit gốc, chỉ dùng createCustomRole/editCustomRole
            Action create = roleModelsTable.getAction("create");
            if (create != null) {
                create.setVisible(false);
            }
            Action edit = roleModelsTable.getAction("edit");
            if (edit != null) {
                edit.setVisible(false);
            }
        }
    }

    /**
     * Chỉ enable "Sửa quyền" khi chọn đúng 1 role source = DATABASE.
     */
    @Install(to = "roleModelsTable.editCustomRole", subject = "enabledRule")
    protected boolean roleModelsTableEditCustomRoleEnabledRule() {
        // Nếu không có RolePersistence thì không cho sửa luôn
        if (rolePersistence == null) {
            return false;
        }
        return isDatabaseRoleSelected();
    }

    /**
     * Helper: kiểm tra có đúng 1 role được chọn và source = DATABASE hay không.
     */
    private boolean isDatabaseRoleSelected() {
        Set<ResourceRoleModel> selected = roleModelsTable.getSelectedItems();
        if (selected.size() == 1) {
            ResourceRoleModel roleModel = selected.iterator().next();
            return RoleSource.DATABASE.equals(roleModel.getSource());
        }
        return false;
    }

    @Subscribe("roleModelsTable.createCustomRole")
    public void onRoleModelsTableCreateCustomRole(final ActionPerformedEvent event) {
        // Nút Thêm mới quyền – tạo role mới trong DB
        viewNavigators.view(this, ResourceRoleEditView.class)
                .withRouteParameters(new RouteParameters("code", NEW_ENTITY_ID))
                .navigate();
    }

    @Subscribe("roleModelsTable.editCustomRole")
    public void onRoleModelsTableEditCustomRole(ActionPerformedEvent e) {
        // Sự kiện chỉ chạy được nếu action đang enabled (tức là đã qua enabledRule ở trên)
        ResourceRoleModel selected = roleModelsTable.getSingleSelectedItem();
        if (selected == null) {
            return;
        }

        String serialized = urlParamSerializer.serialize(selected.getCode());
        viewNavigators.view(this, ResourceRoleEditView.class)
                .withRouteParameters(new RouteParameters("code", serialized))
                .navigate();
    }
}
