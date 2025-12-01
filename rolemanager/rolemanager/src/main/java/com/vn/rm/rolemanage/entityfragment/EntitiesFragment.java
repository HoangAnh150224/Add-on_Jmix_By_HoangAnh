package com.vn.rm.rolemanage.entityfragment;

import com.google.common.base.Strings;
import com.vaadin.flow.component.checkbox.Checkbox;
import com.vaadin.flow.component.grid.HeaderRow;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.data.renderer.LitRenderer;
import com.vn.rm.rolemanage.service.RoleManagerService;
import io.jmix.core.Metadata;
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

    // --- Biến kiểm tra Role ReadOnly ---
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

    // Cache chỉ dùng cho dữ liệu Attribute
    private final Map<String, List<AttributeResourceModel>> attrCache = new HashMap<>();

    // Template HTML đơn giản cho Checkbox (Đã bỏ indeterminate)
    private static final String CHECKBOX_RENDERER_HTML =
            "<vaadin-checkbox " +
                    "?checked='${item.checked}' " +
                    "?disabled='${item.disabled}' " +
                    "@change='${handleChange}'></vaadin-checkbox>";

    // ========================================================================
    // Setter & External Logic
    // ========================================================================
    public void setRoleReadOnly(boolean readOnly) {
        this.isRoleReadOnly = readOnly;
        updateHeadersState();
        if (entityMatrixTable != null) entityMatrixTable.getDataProvider().refreshAll();
        if (attrMatrixTable != null) attrMatrixTable.getDataProvider().refreshAll();
    }

    private void updateHeadersState() {
        boolean enabled = !isRoleReadOnly;
        if (headerAllowAllCb != null) headerAllowAllCb.setEnabled(enabled);
        if (headerCreateCb != null) headerCreateCb.setEnabled(enabled);
        if (headerReadCb != null) headerReadCb.setEnabled(enabled);
        if (headerUpdateCb != null) headerUpdateCb.setEnabled(enabled);
        if (headerDeleteCb != null) headerDeleteCb.setEnabled(enabled);
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    @Subscribe
    public void onReady(ReadyEvent event) {
        attrCache.clear();
        entityMatrixTable.setSelectionMode(DataGrid.SelectionMode.SINGLE);

        installMatrixColumns();
        installAttrColumns();
        initEntityHeader();
        initAttrHeader();

        if (entityMatrixDc.getItems().isEmpty()) {
            List<EntityMatrixRow> rows = roleManagerService.createMatrixEntity();
            entityMatrixDc.setItems(rows);
        }
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
            List<EntityMatrixRow> rows = roleManagerService.createMatrixEntity();
            entityMatrixDc.setItems(rows);
        }
        refreshMatrixFromPolicies();
    }

    private void refreshMatrixFromPolicies() {
        List<EntityMatrixRow> rows = new ArrayList<>(entityMatrixDc.getItems());
        Collection<ResourcePolicyModel> policies =
                Optional.ofNullable(resourcePoliciesDc.getItems()).orElseGet(List::of);

        attrCache.clear();
        roleManagerService.updateEntityMatrix(rows, policies, attrCache);

        entityMatrixDc.setItems(rows);
        updateHeaderAllowAllFromRows();

        attrMatrixDc.setItems(Collections.emptyList());
        if (attrEntityLabel != null) attrEntityLabel.setText("");
    }

    // ========================================================================
    // Logic: Load & Apply Attributes
    // ========================================================================

    private void loadAttributesForEntity(String entityName) {
        if (Strings.isNullOrEmpty(entityName) || "*".equals(entityName.trim()) || "All entities (*)".equals(entityName)) {
            if (attrEntityLabel != null) attrEntityLabel.setText("");
            attrMatrixDc.setItems(Collections.emptyList());
            updateAttrHeaderState(true);
            return;
        }

        if (attrEntityLabel != null) attrEntityLabel.setText("Entity: " + entityName);

        List<AttributeResourceModel> rows = attrCache.computeIfAbsent(entityName, k -> {
            List<AttributeResourceModel> fromService = roleManagerService.buildAttrRowsForEntity(k);
            if (fromService == null) return new ArrayList<>();
            return new ArrayList<>(fromService);
        });

        attrMatrixDc.setItems(new ArrayList<>(rows));
        updateAttrHeaderState(false);
        updateAttrHeaderFromRows();
    }

    private void updateEntityAttributesSummary(String entityName) {
        List<AttributeResourceModel> attributesForThisEntity = attrCache.get(entityName);
        if (attributesForThisEntity == null) {
            attributesForThisEntity = roleManagerService.buildAttrRowsForEntity(entityName);
            attrCache.put(entityName, attributesForThisEntity);
        }

        roleManagerService.updateEntityAttributesSummary(
                entityName,
                entityMatrixDc.getItems(),
                attributesForThisEntity,
                attrCache
        );
    }

    private void updateAttrHeaderState(boolean disabled) {
        boolean canEdit = !disabled && !isRoleReadOnly;
        if (headerAttrModifyCb != null) headerAttrModifyCb.setEnabled(canEdit);
        if (headerAttrViewCb != null) headerAttrViewCb.setEnabled(canEdit);
    }

    private void resetAllAttributesFlags() {
        attrCache.values().forEach(list -> {
            for (AttributeResourceModel a : list) {
                a.setView(false);
                a.setModify(false);
            }
        });

        List<AttributeResourceModel> currentAttrs = attrMatrixDc.getItems();
        if (!currentAttrs.isEmpty()) {
            attrMatrixTable.getDataProvider().refreshAll();
        }

        List<EntityMatrixRow> entities = entityMatrixDc.getItems();
        for (EntityMatrixRow r : entities) r.setAttributes(null);
        entityMatrixTable.getDataProvider().refreshAll();

        if (headerAttrViewCb != null) headerAttrViewCb.setValue(false);
        if (headerAttrModifyCb != null) headerAttrModifyCb.setValue(false);
    }

    // ========================================================================
    // Entity Matrix Columns
    // ========================================================================

    private void installMatrixColumns() {
        DataGrid.Column<EntityMatrixRow> allowAllCol = entityMatrixTable.getColumnByKey("allowAllCol");
        if (allowAllCol != null) {
            // Sử dụng HTML đơn giản đã bỏ indeterminate
            allowAllCol.setRenderer(LitRenderer.<EntityMatrixRow>of(CHECKBOX_RENDERER_HTML)
                    .withProperty("checked", row -> T(row.getAllowAll()))
                    .withProperty("disabled", row -> isRoleReadOnly)
                    .withFunction("handleChange", row -> {
                        boolean newVal = !T(row.getAllowAll());
                        row.setAllowAll(newVal);
                        row.setCanCreate(newVal);
                        row.setCanRead(newVal);
                        row.setCanUpdate(newVal);
                        row.setCanDelete(newVal);

                        entityMatrixTable.getDataProvider().refreshItem(row);
                        updateHeaderAllowAllFromRows();
                    }));
        }

        installPermissionColumn("createCol", EntityMatrixRow::getCanCreate, EntityMatrixRow::setCanCreate);
        installPermissionColumn("readCol", EntityMatrixRow::getCanRead, EntityMatrixRow::setCanRead);
        installPermissionColumn("updateCol", EntityMatrixRow::getCanUpdate, EntityMatrixRow::setCanUpdate);
        installPermissionColumn("deleteCol", EntityMatrixRow::getCanDelete, EntityMatrixRow::setCanDelete);

        DataGrid.Column<EntityMatrixRow> attrCol = entityMatrixTable.getColumnByKey("attributesCol");
        if (attrCol != null) {
            attrCol.setRenderer(LitRenderer.<EntityMatrixRow>of(
                            "<span style='font-size: var(--lumo-font-size-s);'>${item.text}</span>")
                    .withProperty("text", row -> Strings.nullToEmpty(row.getAttributes())));
        }
    }

    private void installPermissionColumn(String colId, Function<EntityMatrixRow, Boolean> getter, BiConsumer<EntityMatrixRow, Boolean> setter) {
        DataGrid.Column<EntityMatrixRow> col = entityMatrixTable.getColumnByKey(colId);
        if (col != null) {
            col.setRenderer(LitRenderer.<EntityMatrixRow>of(CHECKBOX_RENDERER_HTML)
                    .withProperty("checked", row -> T(getter.apply(row)))
                    .withProperty("disabled", row -> isRoleReadOnly)
                    .withFunction("handleChange", row -> {
                        boolean newVal = !T(getter.apply(row));
                        setter.accept(row, newVal);
                        roleManagerService.syncAllowAll(row);
                        entityMatrixTable.getDataProvider().refreshItem(row);
                        updateHeaderAllowAllFromRows();
                    }));
        }
    }

    // ========================================================================
    // Attribute Matrix Columns
    // ========================================================================

    private void installAttrColumns() {
        DataGrid.Column<AttributeResourceModel> nameCol = attrMatrixTable.getColumnByKey("attribute");
        if (nameCol != null) {
            nameCol.setRenderer(LitRenderer.<AttributeResourceModel>of("<span>${item.name}</span>")
                    .withProperty("name", row -> Strings.nullToEmpty(row.getName())));
        }

        installAttrCheckboxColumn("viewCol", AttributeResourceModel::getView, (row, v) -> {
            row.setView(v);
            if (v) row.setModify(false);
        });

        installAttrCheckboxColumn("modifyCol", AttributeResourceModel::getModify, (row, v) -> {
            row.setModify(v);
            if (v) row.setView(false);
        });
    }

    private void installAttrCheckboxColumn(String colId, Function<AttributeResourceModel, Boolean> getter, BiConsumer<AttributeResourceModel, Boolean> setter) {
        DataGrid.Column<AttributeResourceModel> col = attrMatrixTable.getColumnByKey(colId);
        if (col != null) {
            col.setRenderer(LitRenderer.<AttributeResourceModel>of(CHECKBOX_RENDERER_HTML)
                    .withProperty("checked", row -> T(getter.apply(row)))
                    .withProperty("disabled", row -> isRoleReadOnly)
                    .withFunction("handleChange", row -> {
                        boolean newVal = !T(getter.apply(row));
                        setter.accept(row, newVal);

                        attrMatrixTable.getDataProvider().refreshItem(row);
                        updateAttrHeaderFromRows();

                        EntityMatrixRow currentEntity = entityMatrixDc.getItemOrNull();
                        if (currentEntity != null) {
                            List<AttributeResourceModel> currentItems = attrMatrixDc.getItems();
                            attrCache.put(currentEntity.getEntityName(), new ArrayList<>(currentItems));

                            updateEntityAttributesSummary(currentEntity.getEntityName());
                            entityMatrixTable.getDataProvider().refreshItem(currentEntity);
                        }
                    }));
        }
    }

    // ========================================================================
    // Header Components
    // ========================================================================

    protected void initEntityHeader() {
        HeaderRow row = entityMatrixTable.appendHeaderRow();
        DataGrid.Column<EntityMatrixRow> entityCol = entityMatrixTable.getColumns().isEmpty() ? null : entityMatrixTable.getColumns().get(0);
        if (entityCol != null) row.getCell(entityCol).setText("All entities (*)");

        headerAllowAllCb = createHeaderCheckbox(row, "allowAllCol", (r, v) -> {
            if (isRoleReadOnly) return;
            r.setAllowAll(v);
            r.setCanCreate(v);
            r.setCanRead(v);
            r.setCanUpdate(v);
            r.setCanDelete(v);
        });

        if (headerAllowAllCb != null) {
            headerAllowAllCb.addValueChangeListener(e -> {
                if (updatingHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());

                List<EntityMatrixRow> items = new ArrayList<>(entityMatrixDc.getItems());
                for (EntityMatrixRow r : items) {
                    if (!isRoleReadOnly) {
                        r.setAllowAll(v);
                        r.setCanCreate(v);
                        r.setCanRead(v);
                        r.setCanUpdate(v);
                        r.setCanDelete(v);

                        if (v) {
                            List<AttributeResourceModel> attrs = attrCache.computeIfAbsent(r.getEntityName(),
                                    k -> roleManagerService.buildAttrRowsForEntity(k));
                            for (AttributeResourceModel a : attrs) {
                                a.setModify(true);
                                a.setView(false);
                            }
                            roleManagerService.updateEntityAttributesSummary(r.getEntityName(), items, attrs, attrCache);
                        }
                    }
                }

                if (!v) {
                    resetAllAttributesFlags();
                }

                entityMatrixTable.getDataProvider().refreshAll();

                EntityMatrixRow current = entityMatrixDc.getItemOrNull();
                if (current != null) {
                    loadAttributesForEntity(current.getEntityName());
                }

                updateHeaderAllowAllFromRows();
            });
        }

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

        if (!"allowAllCol".equals(colKey)) {
            cb.addValueChangeListener(e -> {
                if (updatingHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());
                List<EntityMatrixRow> items = new ArrayList<>(entityMatrixDc.getItems());
                for (EntityMatrixRow r : items) logic.accept(r, v);
                entityMatrixTable.getDataProvider().refreshAll();
                updateHeaderAllowAllFromRows();
            });
        }

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
                List<AttributeResourceModel> items = attrMatrixDc.getItems();
                items.forEach(r -> {
                    r.setView(v);
                    if (v) r.setModify(false);
                });
                attrMatrixTable.getDataProvider().refreshAll();
                updateAttrHeaderFromRows();

                EntityMatrixRow currentEntity = entityMatrixDc.getItemOrNull();
                if (currentEntity != null) {
                    attrCache.put(currentEntity.getEntityName(), new ArrayList<>(items));
                    updateEntityAttributesSummary(currentEntity.getEntityName());
                    entityMatrixTable.getDataProvider().refreshItem(currentEntity);
                }
            });
            row.getCell(viewCol).setComponent(headerAttrViewCb);
        }

        if (modifyCol != null) {
            headerAttrModifyCb = new Checkbox();
            headerAttrModifyCb.addValueChangeListener(e -> {
                if (updatingAttrHeaderFromRows || !e.isFromClient()) return;
                boolean v = Boolean.TRUE.equals(e.getValue());
                List<AttributeResourceModel> items = attrMatrixDc.getItems();
                items.forEach(r -> {
                    r.setModify(v);
                    if (v) r.setView(false);
                });
                attrMatrixTable.getDataProvider().refreshAll();
                updateAttrHeaderFromRows();

                EntityMatrixRow currentEntity = entityMatrixDc.getItemOrNull();
                if (currentEntity != null) {
                    attrCache.put(currentEntity.getEntityName(), new ArrayList<>(items));
                    updateEntityAttributesSummary(currentEntity.getEntityName());
                    entityMatrixTable.getDataProvider().refreshItem(currentEntity);
                }
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

    public List<ResourcePolicyModel> buildPoliciesFromMatrix() {
        return roleManagerService.buildPoliciesFromMatrix(new ArrayList<>(entityMatrixDc.getItems()), attrCache);
    }

    private static boolean T(Boolean b) {
        return Boolean.TRUE.equals(b);
    }
}