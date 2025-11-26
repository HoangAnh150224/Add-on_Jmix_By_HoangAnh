package com.vn.rm.rolemanage.entityfragment;

import com.google.common.base.Strings;
import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.grid.HeaderRow;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.data.renderer.ComponentRenderer;
import com.vn.rm.rolemanage.service.RoleManagerService;
import io.jmix.core.Metadata;
import io.jmix.core.MetadataTools;
import io.jmix.flowui.component.grid.DataGrid;
import io.jmix.flowui.fragment.Fragment;
import io.jmix.flowui.fragment.FragmentDescriptor;
import io.jmix.flowui.model.CollectionContainer;
import io.jmix.flowui.view.Subscribe;
import io.jmix.flowui.view.Target;
import io.jmix.flowui.view.ViewComponent;
import io.jmix.security.model.ResourcePolicyModel;
import io.jmix.securityflowui.view.resourcepolicy.AttributeResourceModel;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Function;

@FragmentDescriptor("entities-fragment.xml")
public class EntitiesFragment extends Fragment<VerticalLayout> {

    @ViewComponent
    private CollectionContainer<ResourcePolicyModel> resourcePoliciesDc;

    @ViewComponent
    private CollectionContainer<EntityMatrixRow> entityMatrixDc;
    @ViewComponent
    private DataGrid<EntityMatrixRow> entityMatrixTable;

    @ViewComponent
    private CollectionContainer<AttributeResourceModel> attrMatrixDc;
    @ViewComponent
    private DataGrid<AttributeResourceModel> attrMatrixTable;

    @ViewComponent
    private Span attrEntityLabel;

    @Autowired
    private RoleManagerService roleManagerService;

    @Autowired
    private Metadata metadata;

    @Autowired
    private MetadataTools metadataTools;

    // --- Biến kiểm tra Role ReadOnly (Annotated Class) ---
    private boolean isRoleReadOnly = false;

    // Headers Entity
    private Checkbox headerAllowAllCb;
    private Checkbox headerCreateCb;
    private Checkbox headerReadCb;
    private Checkbox headerUpdateCb;
    private Checkbox headerDeleteCb;

    // Headers Attribute
    private Checkbox headerAttrViewCb;
    private Checkbox headerAttrModifyCb;

    private boolean updatingHeaderFromRows = false;
    private boolean updatingAttrHeaderFromRows = false;
    private boolean syncingAttrSummary = false;

    private final Map<String, List<AttributeResourceModel>> attrCache = new HashMap<>();
    private final Map<String, Checkbox> entityCellCache = new HashMap<>();
    private final Map<String, TextField> entityAttrFieldCache = new HashMap<>();

    // ========================================================================
    // Setter để View bên ngoài gọi vào (Xử lý Read-only)
    // ========================================================================
    public void setRoleReadOnly(boolean readOnly) {
        this.isRoleReadOnly = readOnly;

        // 1. Cập nhật trạng thái các nút trên Header
        updateHeadersState();

        // 2. Refresh lại dữ liệu bảng Entity để các dòng kích hoạt lại logic render (Disable checkbox)
        if (entityMatrixDc != null && !entityMatrixDc.getItems().isEmpty()) {
            List<EntityMatrixRow> currentRows = new ArrayList<>(entityMatrixDc.getItems());
            // Clear cache để renderer tạo lại component mới với trạng thái disabled
            entityCellCache.clear();
            entityAttrFieldCache.clear();
            entityMatrixDc.setItems(currentRows);
        }

        // 3. Refresh lại dữ liệu bảng Attribute
        if (attrMatrixDc != null && !attrMatrixDc.getItems().isEmpty()) {
            List<AttributeResourceModel> currentAttrs = new ArrayList<>(attrMatrixDc.getItems());
            attrMatrixDc.setItems(currentAttrs);
        }
    }

    private void updateHeadersState() {
        boolean enabled = !isRoleReadOnly;
        if (headerAllowAllCb != null) headerAllowAllCb.setEnabled(enabled);
        if (headerCreateCb != null) headerCreateCb.setEnabled(enabled);
        if (headerReadCb != null) headerReadCb.setEnabled(enabled);
        if (headerUpdateCb != null) headerUpdateCb.setEnabled(enabled);
        if (headerDeleteCb != null) headerDeleteCb.setEnabled(enabled);
        // Header attribute sẽ được update khi load entity cụ thể
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    @Subscribe
    public void onReady(ReadyEvent event) {
        entityMatrixTable.setSelectionMode(DataGrid.SelectionMode.SINGLE);
        List<EntityMatrixRow> rows = roleManagerService.createMatrixEntity();
        entityMatrixDc.setItems(rows);

        installMatrixColumns();
        installAttrColumns();
        initEntityHeader();
        initAttrHeader();
        updateHeadersState();
    }

    @Subscribe(id = "entityMatrixDc", target = Target.DATA_CONTAINER)
    public void onEntityMatrixItemChange(CollectionContainer.ItemChangeEvent<EntityMatrixRow> e) {
        EntityMatrixRow row = e.getItem();
        if (row == null) {
            if (attrEntityLabel != null) attrEntityLabel.setText("");
            attrMatrixDc.setItems(Collections.emptyList());
            updateAttrHeaderState(true);
            return;
        }

        String cap = Optional.ofNullable(row.getEntityCaption()).orElse(row.getEntityName());
        if (attrEntityLabel != null) {
            attrEntityLabel.setText("Entity: " + cap + " (" + row.getEntityName() + ")");
        }
        loadAttributesForEntity(row.getEntityName());
    }

    public void initPolicies(Collection<ResourcePolicyModel> policies) {
        if (policies != null) {
            resourcePoliciesDc.setItems(new ArrayList<>(policies));
        } else {
            resourcePoliciesDc.setItems(Collections.emptyList());
        }

        if (entityMatrixDc.getItems().isEmpty()) {
            entityMatrixTable.setSelectionMode(DataGrid.SelectionMode.SINGLE);
            List<EntityMatrixRow> rows = roleManagerService.createMatrixEntity();
            entityMatrixDc.setItems(rows);
            installMatrixColumns();
            installAttrColumns();
            initEntityHeader();
            initAttrHeader();
        }
        refreshMatrixFromPolicies();
    }

    private void refreshMatrixFromPolicies() {
        List<EntityMatrixRow> rows = new ArrayList<>(entityMatrixDc.getItems());
        Collection<ResourcePolicyModel> policies =
                Optional.ofNullable(resourcePoliciesDc.getItems()).orElseGet(List::of);

        roleManagerService.updateEntityMatrix(rows, policies, attrCache);

        entityCellCache.clear();
        entityAttrFieldCache.clear();

        entityMatrixDc.setItems(rows);
        updateHeaderAllowAllFromRows();

        attrMatrixDc.setItems(Collections.emptyList());
        if (attrEntityLabel != null) attrEntityLabel.setText("");
    }

    /**
     * Kiểm tra xem Entity có bị ReadOnly hay không.
     * SỬA ĐỔI: Luôn trả về FALSE để cho phép sửa cả DTO.
     */
    private boolean isReadOnlyEntity(String entityName) {
        return false;
    }

    // ========================================================================
    // Header Logic
    // ========================================================================

    protected void initEntityHeader() {
        HeaderRow row = entityMatrixTable.appendHeaderRow();
        DataGrid.Column<EntityMatrixRow> entityCol = entityMatrixTable.getColumns().isEmpty() ? null : entityMatrixTable.getColumns().get(0);
        if (entityCol != null) row.getCell(entityCol).setText("All entities (*)");

        headerAllowAllCb = createHeaderCheckbox(row, "allowAllCol", (r, v) -> {
            if (isRoleReadOnly) return; // Chỉ chặn nếu là Role hệ thống

            r.setAllowAll(v);
            r.setCanCreate(v);
            r.setCanRead(v);
            r.setCanUpdate(v);
            r.setCanDelete(v);

            // --- LOGIC MỚI: Header Allow All -> Attribute Modify ---
            applyAllowAllToAttributes(r.getEntityName(), v);
        });

        headerCreateCb = createHeaderCheckbox(row, "createCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setCanCreate(v);
            roleManagerService.syncAllowAll(r);
        });
        headerReadCb = createHeaderCheckbox(row, "readCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setCanRead(v);
            roleManagerService.syncAllowAll(r);
        });
        headerUpdateCb = createHeaderCheckbox(row, "updateCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setCanUpdate(v);
            roleManagerService.syncAllowAll(r);
        });
        headerDeleteCb = createHeaderCheckbox(row, "deleteCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setCanDelete(v);
            roleManagerService.syncAllowAll(r);
        });

        updateHeadersState();
    }

    private Checkbox createHeaderCheckbox(HeaderRow headerRow, String colKey, BiConsumer<EntityMatrixRow, Boolean> logic) {
        DataGrid.Column<EntityMatrixRow> col = entityMatrixTable.getColumnByKey(colKey);
        if (col == null) return null;
        Checkbox cb = new Checkbox();
        cb.addValueChangeListener(e -> {
            if (updatingHeaderFromRows || !e.isFromClient()) return;
            boolean v = Boolean.TRUE.equals(e.getValue());
            List<EntityMatrixRow> items = new ArrayList<>(entityMatrixDc.getItems());
            for (EntityMatrixRow r : items) logic.accept(r, v);

            if (cb == headerAllowAllCb && !v) resetAllAttributesFlags();

            entityMatrixDc.setItems(items);
            entityCellCache.clear();
            updateHeaderAllowAllFromRows();
        });
        headerRow.getCell(col).setComponent(cb);
        return cb;
    }

    private void updateHeaderAllowAllFromRows() {
        if (headerAllowAllCb == null) return;
        updatingHeaderFromRows = true;
        try {
            List<EntityMatrixRow> items = entityMatrixDc.getItems();
            if (items == null || items.isEmpty()) {
                setHeadersValue(false, false, false, false, false);
                return;
            }
            boolean allC = items.stream().allMatch(r -> T(r.getCanCreate()));
            boolean allR = items.stream().allMatch(r -> T(r.getCanRead()));
            boolean allU = items.stream().allMatch(r -> T(r.getCanUpdate()));
            boolean allD = items.stream().allMatch(r -> T(r.getCanDelete()));
            boolean allA = items.stream().allMatch(r -> T(r.getAllowAll()));
            setHeadersValue(allA, allC, allR, allU, allD);
        } finally {
            updatingHeaderFromRows = false;
        }
    }

    private void setHeadersValue(boolean all, boolean c, boolean r, boolean u, boolean d) {
        if (headerAllowAllCb != null) headerAllowAllCb.setValue(all);
        if (headerCreateCb != null) headerCreateCb.setValue(c);
        if (headerReadCb != null) headerReadCb.setValue(r);
        if (headerUpdateCb != null) headerUpdateCb.setValue(u);
        if (headerDeleteCb != null) headerDeleteCb.setValue(d);
    }

    private void initAttrHeader() {
        HeaderRow row = attrMatrixTable.appendHeaderRow();
        DataGrid.Column<AttributeResourceModel> attrCol = attrMatrixTable.getColumnByKey("name");
        DataGrid.Column<AttributeResourceModel> viewCol = attrMatrixTable.getColumnByKey("viewCol");
        DataGrid.Column<AttributeResourceModel> modifyCol = attrMatrixTable.getColumnByKey("modifyCol");
        if (attrCol != null) row.getCell(attrCol).setText("All attributes (*)");

        if (viewCol != null) {
            headerAttrViewCb = new Checkbox();
            headerAttrViewCb.addValueChangeListener(e -> {
                if (updatingAttrHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());
                List<AttributeResourceModel> items = new ArrayList<>(attrMatrixDc.getItems());
                items.forEach(r -> {
                    r.setView(v);
                    if (v) r.setModify(false);
                });
                attrMatrixDc.setItems(items);
                updateAttrHeaderFromRows();
                EntityMatrixRow c = entityMatrixDc.getItemOrNull();
                if (c != null) updateEntityAttributesSummarySafe(c.getEntityName());
            });
            row.getCell(viewCol).setComponent(headerAttrViewCb);
        }
        if (modifyCol != null) {
            headerAttrModifyCb = new Checkbox();
            headerAttrModifyCb.addValueChangeListener(e -> {
                if (updatingAttrHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());
                List<AttributeResourceModel> items = new ArrayList<>(attrMatrixDc.getItems());
                items.forEach(r -> {
                    r.setModify(v);
                    if (v) r.setView(false);
                });
                attrMatrixDc.setItems(items);
                updateAttrHeaderFromRows();
                EntityMatrixRow c = entityMatrixDc.getItemOrNull();
                if (c != null) updateEntityAttributesSummarySafe(c.getEntityName());
            });
            row.getCell(modifyCol).setComponent(headerAttrModifyCb);
        }
        updateAttrHeaderFromRows();
    }

    private void updateAttrHeaderFromRows() {
        if (headerAttrViewCb == null && headerAttrModifyCb == null) return;
        updatingAttrHeaderFromRows = true;
        try {
            List<AttributeResourceModel> items = attrMatrixDc.getItems();
            if (items == null || items.isEmpty()) {
                if (headerAttrViewCb != null) headerAttrViewCb.setValue(false);
                if (headerAttrModifyCb != null) headerAttrModifyCb.setValue(false);
                return;
            }
            boolean allV = items.stream().allMatch(r -> T(r.getView()));
            boolean allM = items.stream().allMatch(r -> T(r.getModify()));
            if (headerAttrViewCb != null) headerAttrViewCb.setValue(allV);
            if (headerAttrModifyCb != null) headerAttrModifyCb.setValue(allM);
        } finally {
            updatingAttrHeaderFromRows = false;
        }
    }

    // ========================================================================
    // Columns & Permissions Logic
    // ========================================================================

    private void installMatrixColumns() {
        DataGrid.Column<EntityMatrixRow> allowAllCol = entityMatrixTable.getColumnByKey("allowAllCol");
        if (allowAllCol != null) {
            allowAllCol.setRenderer(new ComponentRenderer<>(row -> {
                String key = entityCellKey("allowAll", row);
                Checkbox cb = entityCellCache.computeIfAbsent(key, k -> {
                    Checkbox newCb = new Checkbox();
                    newCb.addValueChangeListener(e -> {
                        if (!e.isFromClient()) return;
                        boolean v = bool(e.getValue());

                        // Set quyền Entity
                        row.setAllowAll(v);
                        row.setCanCreate(v);
                        row.setCanRead(v);
                        row.setCanUpdate(v);
                        row.setCanDelete(v);

                        updateSiblingCheckbox(row, "create", v);
                        updateSiblingCheckbox(row, "read", v);
                        updateSiblingCheckbox(row, "update", v);
                        updateSiblingCheckbox(row, "delete", v);

                        // --- LOGIC MỚI: Row Allow All -> Attribute Modify ---
                        applyAllowAllToAttributes(row.getEntityName(), v);

                        updateHeaderAllowAllFromRows();
                    });
                    return newCb;
                });

                // Chỉ disable nếu Role là ReadOnly (do annotated class)
                // Bỏ logic chặn DTO ở đây
                cb.setEnabled(!isRoleReadOnly);
                cb.setValue(T(row.getAllowAll()));

                return cb;
            }));
        }

        installPermissionColumn("createCol", "create", EntityMatrixRow::getCanCreate, EntityMatrixRow::setCanCreate);
        installPermissionColumn("readCol", "read", EntityMatrixRow::getCanRead, EntityMatrixRow::setCanRead);
        installPermissionColumn("updateCol", "update", EntityMatrixRow::getCanUpdate, EntityMatrixRow::setCanUpdate);
        installPermissionColumn("deleteCol", "delete", EntityMatrixRow::getCanDelete, EntityMatrixRow::setCanDelete);

        DataGrid.Column<EntityMatrixRow> attrCol = entityMatrixTable.getColumnByKey("attributesCol");
        if (attrCol != null) {
            attrCol.setRenderer(new ComponentRenderer<>(row -> {
                String key = "attrTxt|" + row.getEntityName();
                TextField tf = entityAttrFieldCache.computeIfAbsent(key, k -> {
                    TextField t = new TextField();
                    t.setWidthFull();
                    t.setReadOnly(true);
                    return t;
                });
                tf.setValue(Objects.toString(row.getAttributes(), ""));
                return tf;
            }));
        }
    }

    private void installPermissionColumn(String colId, String keyPrefix, Function<EntityMatrixRow, Boolean> getter, BiConsumer<EntityMatrixRow, Boolean> setter) {
        DataGrid.Column<EntityMatrixRow> col = entityMatrixTable.getColumnByKey(colId);
        if (col != null) {
            col.setRenderer(new ComponentRenderer<>(row -> {
                String key = entityCellKey(keyPrefix, row);
                Checkbox cb = entityCellCache.computeIfAbsent(key, k -> {
                    Checkbox newCb = new Checkbox();
                    newCb.addValueChangeListener(e -> {
                        if (!e.isFromClient()) return;
                        boolean v = bool(e.getValue());
                        setter.accept(row, v);
                        roleManagerService.syncAllowAll(row);
                        if (!isRoleReadOnly) {
                            Checkbox allowCb = entityCellCache.get(entityCellKey("allowAll", row));
                            if (allowCb != null) allowCb.setValue(row.getAllowAll());
                        }
                        newCb.setIndeterminate(false);
                        updateHeaderAllowAllFromRows();
                    });
                    return newCb;
                });

                boolean val = T(getter.apply(row));

                if (isRoleReadOnly) {
                    cb.setEnabled(false); // Disable nếu là role hệ thống
                    cb.setValue(val);
                } else {
                    cb.setEnabled(true);
                    cb.setValue(val);
                    if (T(row.getAllowAll()) && val) cb.setIndeterminate(true);
                    else cb.setIndeterminate(false);
                }
                return cb;
            }));
        }
    }

    private void updateSiblingCheckbox(EntityMatrixRow row, String type, boolean value) {
        Checkbox cb = entityCellCache.get(entityCellKey(type, row));
        if (cb != null && cb.isEnabled()) {
            cb.setValue(value);
            cb.setIndeterminate(false);
        }
    }

    private void installAttrColumns() {
        DataGrid.Column<AttributeResourceModel> nameCol = attrMatrixTable.getColumnByKey("attribute");
        if (nameCol != null) nameCol.setRenderer(new ComponentRenderer<>(row -> {
            var span = new Span();
            span.setText(Strings.nullToEmpty(row.getName()));
            return span;
        }));

        installAttrCheckboxColumn("viewCol", AttributeResourceModel::getView, (row, v) -> {
            row.setView(v);
            if (v) row.setModify(false);
        }, false);

        installAttrCheckboxColumn("modifyCol", AttributeResourceModel::getModify, (row, v) -> {
            row.setModify(v);
            if (v) row.setView(false);
        }, true);
    }

    private void installAttrCheckboxColumn(String colId, Function<AttributeResourceModel, Boolean> getter, BiConsumer<AttributeResourceModel, Boolean> setter, boolean isModifyCol) {
        DataGrid.Column<AttributeResourceModel> col = attrMatrixTable.getColumnByKey(colId);
        if (col != null) {
            col.setRenderer(new ComponentRenderer<>(row -> {
                Checkbox cb = new Checkbox();

                boolean val = T(getter.apply(row));

                if (isRoleReadOnly) {
                    cb.setEnabled(false);
                    cb.setValue(val);
                } else {
                    cb.setEnabled(true);
                    cb.setValue(val);
                }

                cb.addValueChangeListener(e -> {
                    if (!e.isFromClient()) return;
                    boolean v = T(e.getValue());
                    setter.accept(row, v);
                    attrMatrixDc.replaceItem(row);
                    updateAttrHeaderFromRows();

                    EntityMatrixRow currentEntity = entityMatrixDc.getItemOrNull();
                    if (currentEntity != null) updateEntityAttributesSummarySafe(currentEntity.getEntityName());
                });
                return cb;
            }));
        }
    }

    private void loadAttributesForEntity(String entityName) {
        if (Strings.isNullOrEmpty(entityName) || "*".equals(entityName.trim())) {
            if (attrEntityLabel != null) attrEntityLabel.setText("");
            attrMatrixDc.setItems(Collections.emptyList());
            updateAttrHeaderState(true);
            return;
        }
        if (attrEntityLabel != null) attrEntityLabel.setText("Entity: " + entityName);

        List<AttributeResourceModel> rows = attrCache.get(entityName);
        if (rows == null) {
            rows = roleManagerService.buildAttrRowsForEntity(entityName);
            attrCache.put(entityName, rows);
        }

        boolean disableControls = isRoleReadOnly;

        if (headerAttrModifyCb != null) {
            headerAttrModifyCb.setEnabled(!disableControls);
        }
        if (headerAttrViewCb != null) {
            headerAttrViewCb.setEnabled(!disableControls);
        }

        attrMatrixDc.setItems(new ArrayList<>(rows));
        updateAttrHeaderFromRows();
        updateEntityAttributesSummarySafe(entityName);
    }

    private void updateAttrHeaderState(boolean disabled) {
        if (headerAttrModifyCb != null) headerAttrModifyCb.setEnabled(!disabled && !isRoleReadOnly);
        if (headerAttrViewCb != null) headerAttrViewCb.setEnabled(!disabled && !isRoleReadOnly);
    }

    private void updateEntityAttributesSummarySafe(String entityName) {
        if (syncingAttrSummary) return;
        try {
            syncingAttrSummary = true;
            updateEntityAttributesSummary(entityName);
        } finally {
            syncingAttrSummary = false;
        }
    }

    private void updateEntityAttributesSummary(String entityName) {
        roleManagerService.updateEntityAttributesSummary(entityName, entityMatrixDc.getItems(), attrMatrixDc.getItems(), attrCache);
        TextField tf = entityAttrFieldCache.get("attrTxt|" + entityName);
        if (tf != null)
            entityMatrixDc.getItems().stream().filter(r -> Objects.equals(r.getEntityName(), entityName)).findFirst().ifPresent(r -> tf.setValue(Objects.toString(r.getAttributes(), "")));
    }

    /**
     * Helper: Khi Allow All -> Set Modify cho tất cả Attributes của Entity đó
     */
    private void applyAllowAllToAttributes(String entityName, boolean allow) {
        if (Strings.isNullOrEmpty(entityName)) return;

        List<AttributeResourceModel> attrs = attrCache.computeIfAbsent(entityName,
                k -> roleManagerService.buildAttrRowsForEntity(k));

        for (AttributeResourceModel attr : attrs) {
            if (allow) {
                // Allow All -> Bật Modify, Tắt View
                attr.setModify(true);
                attr.setView(false);
            } else {
                // Bỏ Allow All -> Reset
                attr.setModify(false);
                attr.setView(false);
            }
        }

        // Nếu Entity này đang được chọn -> Refresh bảng Attribute
        EntityMatrixRow current = entityMatrixDc.getItemOrNull();
        if (current != null && Objects.equals(current.getEntityName(), entityName)) {
            attrMatrixDc.setItems(new ArrayList<>(attrs));
            updateAttrHeaderFromRows();
        }

        updateEntityAttributesSummary(entityName);
    }

    private void resetAllAttributesFlags() {
        attrCache.values().forEach(list -> {
            for (AttributeResourceModel a : list) {
                a.setView(false);
                a.setModify(false);
            }
        });
        List<AttributeResourceModel> current = new ArrayList<>(attrMatrixDc.getItems());
        if (!current.isEmpty()) {
            current.forEach(a -> {
                a.setView(false);
                a.setModify(false);
            });
            attrMatrixDc.setItems(current);
        }
        List<EntityMatrixRow> entities = new ArrayList<>(entityMatrixDc.getItems());
        for (EntityMatrixRow r : entities) r.setAttributes(null);
        entityCellCache.clear();
        entityAttrFieldCache.clear();
        entityMatrixDc.setItems(entities);
        if (headerAttrViewCb != null) headerAttrViewCb.setValue(false);
        if (headerAttrModifyCb != null) headerAttrModifyCb.setValue(false);
    }

    public List<ResourcePolicyModel> buildPoliciesFromMatrix() {
        return roleManagerService.buildPoliciesFromMatrix(new ArrayList<>(entityMatrixDc.getItems()), attrCache);
    }

    private static boolean T(Boolean b) {
        return Boolean.TRUE.equals(b);
    }

    private static Boolean bool(Boolean b) {
        return Boolean.TRUE.equals(b);
    }

    private String entityCellKey(String columnKey, EntityMatrixRow row) {
        return columnKey + "|" + row.getEntityName() + "|" + row.getId();
    }
}